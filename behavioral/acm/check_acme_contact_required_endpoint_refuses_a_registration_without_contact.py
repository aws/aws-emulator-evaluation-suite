"""acme-contact-required-endpoint-refuses-a-registration-without-contact."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "acme-contact-required-endpoint-refuses-a-registration-without-contact"
GROUP = "overly-permissive"
SERVICES = ["acm"]

_ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:"
# Exactly the two RFC 8555 registry types that can express "a required contact was omitted".
_MISSING_CONTACT_TYPES = frozenset({
    _ACME_ERROR_PREFIX + "malformed",
    _ACME_ERROR_PREFIX + "invalidContact",
})

# ===== helpers (self-contained) =====

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on deadline (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _crypto():
    """Lazily import `cryptography`; ImportError propagates if it is absent."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    return hashes, ec, decode_dss_signature


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text):
    padded = text.replace("-", "+").replace("_", "/")
    padded += "=" * ((-len(padded)) % 4)
    return base64.b64decode(padded)


def _http(ctx, url, *, data=None, headers=None, method=None):
    """One HTTP round trip -> (status, lower-cased headers, body). HTTP error STATUS is graded;
    a transport failure is not caught."""
    request = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return (response.status,
                    {k.lower(): v for k, v in response.headers.items()},
                    response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _safe_delete_endpoint(acm, arn):
    """Teardown. Deleting an endpoint cascades its EABs and registered accounts."""
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _safe_delete_eab(acm, arn):
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arn)


def _create_endpoint(ctx, acm, contact):
    """CreateAcmeEndpoint with a given Contact policy; returns the ARN without waiting."""
    arn = _retry_throttle(lambda: acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {
            "AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Contact=contact,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(acm, arn))
    return arn


def _describe_endpoint(acm, arn):
    endpoint = _retry_throttle(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn))["AcmeEndpoint"]
    assert endpoint["Status"] != "FAILED", (
        f"the ACME endpoint {arn} entered FAILED and will never serve a directory: "
        f"{endpoint.get('FailureReason')!r}"
    )
    return endpoint


def _acme_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-eab-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "acm-acme.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "acme-permissions"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                           "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _external_account_binding(ctx, acm, endpoint_arn, role_arn):
    last = None
    for _ in range(12):
        try:
            arn = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn,
            )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(lambda a=arn: _safe_delete_eab(acm, a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(
        f"CreateAcmeExternalAccountBinding never succeeded through IAM propagation: {last}")


def _directory(ctx, directory_url):
    status, _headers, body = _http(ctx, directory_url)
    assert status == 200, (
        f"the ACME directory at {directory_url!r} must be served; got HTTP {status} "
        f"{body[:200]!r}"
    )
    return json.loads(body)


def _fresh_nonce(ctx, new_nonce_url):
    _status, headers, _body = _http(ctx, new_nonce_url, method="HEAD")
    nonce = headers.get("replay-nonce", "")
    assert nonce, (
        f"HEAD {new_nonce_url!r} must return a Replay-Nonce header; got {sorted(headers)}")
    return nonce


def _account_key():
    _hashes, ec, _decode = _crypto()
    return ec.generate_private_key(ec.SECP256R1())


def _jwk(private_key):
    numbers = private_key.public_key().public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _es256(private_key, protected_b64, payload_b64):
    hashes, ec, decode_dss_signature = _crypto()
    der = private_key.sign(
        f"{protected_b64}.{payload_b64}".encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _eab_jws(mac_key, key_id, new_account_url, jwk):
    protected = _b64url(json.dumps(
        {"alg": "HS256", "kid": key_id, "url": new_account_url}).encode())
    payload = _b64url(json.dumps(jwk).encode())
    signature = _b64url(
        hmac.new(mac_key, f"{protected}.{payload}".encode(), hashlib.sha256).digest())
    return {"protected": protected, "payload": payload, "signature": signature}


def _post_new_account(ctx, new_account_url, nonce, key, payload_obj):
    protected = _b64url(json.dumps(
        {"alg": "ES256", "jwk": _jwk(key), "nonce": nonce, "url": new_account_url}).encode())
    payload = _b64url(json.dumps(payload_obj).encode())
    body = json.dumps({
        "protected": protected,
        "payload": payload,
        "signature": _es256(key, protected, payload),
    }).encode()
    return _http(ctx, new_account_url, data=body,
                 headers={"Content-Type": "application/jose+json"}, method="POST")


def _problem(raw):
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise AssertionError(
            f"an ACME error must be a JSON problem document (RFC 8555 §6.7); got {raw[:300]!r}"
        ) from None
    assert isinstance(parsed, dict), (
        f"an ACME problem document must be a JSON object; got {parsed!r}")
    return parsed


def _account_urls(acm, endpoint_arn):
    urls, token = set(), None
    while True:
        kwargs = {"AcmeEndpointArn": endpoint_arn}
        if token:
            kwargs["NextToken"] = token
        page = _retry_throttle(lambda kw=dict(kwargs): acm.list_acme_accounts(**kw))
        for account in page["AcmeAccounts"]:
            urls.add(account["AccountUrl"])
        token = page.get("NextToken")
        if not token:
            return urls


def _registration(mac_key, key_id, new_account_url, key, *, contact=None):
    """A newAccount payload, with or without the RFC 8555 §7.3 `contact` member."""
    payload = {
        "termsOfServiceAgreed": True,
        "externalAccountBinding": _eab_jws(mac_key, key_id, new_account_url, _jwk(key)),
    }
    if contact is not None:
        payload["contact"] = list(contact)
    return payload


# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An endpoint created with Contact=REQUIRED refuses an ACME registration that omits
    `contact` (a NOT_REQUIRED twin accepts the same one), and with the contact supplied the
    registration succeeds and DescribeAcmeAccount reports exactly that contact.
    Reference: https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-endpoints.html
    """
    acm = ctx.client("acm")
    role_arn = _acme_role(ctx)

    required_arn = _create_endpoint(ctx, acm, "REQUIRED")
    optional_arn = _create_endpoint(ctx, acm, "NOT_REQUIRED")

    # One poll for both, so the twin really is provisioned in the same window.
    endpoints = _poll_until(
        lambda: {arn: _describe_endpoint(acm, arn) for arn in (required_arn, optional_arn)},
        lambda pair: all(ep["Status"] == "ACTIVE" for ep in pair.values()),
        timeout_s=300, interval_s=5,
        description="both ACME endpoints reaching ACTIVE",
    )
    assert endpoints[required_arn]["Contact"] == "REQUIRED", (
        f"the endpoint under test must report Contact=REQUIRED; got "
        f"{endpoints[required_arn]['Contact']!r}"
    )
    assert endpoints[optional_arn]["Contact"] == "NOT_REQUIRED", (
        f"the twin control must report Contact=NOT_REQUIRED; got "
        f"{endpoints[optional_arn]['Contact']!r}"
    )

    wiring = {}
    for arn in (required_arn, optional_arn):
        eab_arn = _external_account_binding(ctx, acm, arn, role_arn)
        credentials = _retry_throttle(
            lambda a=eab_arn: acm.get_acme_external_account_binding_credentials(
                AcmeExternalAccountBindingArn=a))
        mac_key = _b64url_decode(credentials["MacKey"])
        assert mac_key, f"the EAB for {arn} returned an empty MacKey"
        directory = _directory(ctx, endpoints[arn]["EndpointUrl"])
        wiring[arn] = {
            "key_id": credentials["KeyId"],
            "mac_key": mac_key,
            "new_account": directory["newAccount"],
            "new_nonce": directory["newNonce"],
        }

    # --- beat 1: positive control on the NOT_REQUIRED twin, contact omitted. ---
    twin = wiring[optional_arn]
    twin_key = _account_key()
    status, headers, raw = _post_new_account(ctx,
        twin["new_account"], _fresh_nonce(ctx, twin["new_nonce"]), twin_key,
        _registration(twin["mac_key"], twin["key_id"], twin["new_account"], twin_key),
    )
    assert status in (200, 201), (
        f"a contact-less registration must be ACCEPTED by a Contact=NOT_REQUIRED endpoint; got "
        f"HTTP {status} {raw[:300]!r} -- if this leg fails the negative below proves nothing"
    )
    twin_url = headers.get("location", "")
    assert twin_url, (
        f"the accepted registration must return a Location header; headers were "
        f"{sorted(headers)}"
    )
    twin_account = _poll_until(
        lambda: _retry_throttle(lambda: acm.describe_acme_account(
            AcmeEndpointArn=optional_arn, AccountUrl=twin_url))["AcmeAccount"],
        lambda account: account["Status"] == "VALID",
        timeout_s=60, interval_s=3,
        description="ACM reporting the twin's contact-less account VALID",
    )
    # An absent Contacts field and an empty list both mean 'no contact', so `assert not` is right here.
    assert not twin_account.get("Contacts"), (
        f"a registration that supplied no contact must leave Contacts unset; ACM reports "
        f"{twin_account.get('Contacts')!r}"
    )

    # --- beat 2: break exactly ONE thing -- the same request, REQUIRED endpoint. ---
    target = wiring[required_arn]
    denied_key = _account_key()
    status, denied_headers, raw = _post_new_account(ctx,
        target["new_account"], _fresh_nonce(ctx, target["new_nonce"]), denied_key,
        _registration(target["mac_key"], target["key_id"], target["new_account"], denied_key),
    )

    # --- beat 3: the specific refusal. ---
    assert status not in (200, 201), (
        f"a Contact=REQUIRED endpoint must reject a registration that omits `contact`; it "
        f"answered HTTP {status} with Location {denied_headers.get('location')!r} -- and the "
        f"twin control proves a contact-less registration is otherwise accepted, so this is "
        f"the setting doing nothing"
    )
    assert status == 400, (
        f"the refusal is expected as HTTP 400 (a malformed/unacceptable registration); got "
        f"{status} with body {raw[:200]!r}"
    )
    problem = _problem(raw)
    problem_type = problem.get("type", "<absent>")
    # (3a) structural: an RFC 8555 server types its errors.
    assert isinstance(problem_type, str) and problem_type.startswith(_ACME_ERROR_PREFIX), (
        f"an ACME refusal must carry an RFC 8555 §6.7 problem type under "
        f"{_ACME_ERROR_PREFIX!r}; got {problem_type!r} in {problem!r}"
    )
    # (3b) one of the two registry types that can express this, out of ~20.
    assert problem_type in _MISSING_CONTACT_TYPES, (
        f"omitting a required contact must be refused as one of "
        f"{sorted(_MISSING_CONTACT_TYPES)}; got {problem_type!r} (detail "
        f"{problem.get('detail')!r})"
    )

    # --- beat 4: the effect is ABSENT at the destination. ---
    assert not denied_headers.get("location"), (
        f"the refused registration returned a Location header "
        f"{denied_headers.get('location')!r}, so an account WAS created"
    )
    registered = _account_urls(acm, required_arn)
    assert registered == set(), (
        f"this check created the REQUIRED endpoint moments ago and its only registration was "
        f"refused, so ListAcmeAccounts must be empty; it holds {sorted(registered)}"
    )

    # --- beats 5 and 6: restore -- supply the contact; the same call now succeeds. ---
    contact = [f"mailto:{ctx.unique_name('sim2real-acme-')}@example.com"]
    restored_key = _account_key()
    status, headers, raw = _post_new_account(ctx,
        target["new_account"], _fresh_nonce(ctx, target["new_nonce"]), restored_key,
        _registration(target["mac_key"], target["key_id"], target["new_account"],
                      restored_key, contact=contact),
    )
    assert status in (200, 201), (
        f"supplying `contact` must make the identical registration succeed on a "
        f"Contact=REQUIRED endpoint; got HTTP {status} {raw[:300]!r}"
    )
    restored_url = headers.get("location", "")
    assert restored_url, (
        f"the restored registration must return a Location header; headers were "
        f"{sorted(headers)}"
    )

    # Terminal read: the contact crossed from an RFC 8555 JWS payload into the AWS control
    # plane, and is read back through an operation that never saw the HTTPS request.
    restored_account = _poll_until(
        lambda: _retry_throttle(lambda: acm.describe_acme_account(
            AcmeEndpointArn=required_arn, AccountUrl=restored_url))["AcmeAccount"],
        lambda account: account["Status"] == "VALID",
        timeout_s=60, interval_s=3,
        description="ACM reporting the restored account VALID",
    )
    assert restored_account["Contacts"] == contact, (
        f"DescribeAcmeAccount must report exactly the contact the ACME registration supplied; "
        f"got {restored_account['Contacts']!r}, expected {contact!r}"
    )
    final = _account_urls(acm, required_arn)
    assert final == {restored_url}, (
        f"the REQUIRED endpoint must hold exactly the one accepted registration; "
        f"ListAcmeAccounts holds {sorted(final)}, expected {[restored_url]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
