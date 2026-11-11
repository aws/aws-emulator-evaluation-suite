"""acme-new-account-with-a-forged-eab-mac-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "acme-new-account-with-a-forged-eab-mac-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]

_ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:"
# The exact problem type; the prefix above is the structural half.
_EXPECTED_PROBLEM = _ACME_ERROR_PREFIX + "unauthorized"

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
    """One HTTP round trip -> (status, lower-cased headers, body).

    An HTTP error STATUS is a value this check grades, so HTTPError is converted. A transport
    failure is NOT caught: an unreachable ACME endpoint is a failure, not a status code.
    """
    request = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return (response.status,
                    {k.lower(): v for k, v in response.headers.items()},
                    response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _safe_delete_endpoint(acm, arn):
    """Teardown only. Deleting the endpoint cascades its EABs and accounts (ACM User Guide,
    "Managing ACME endpoints"), so this is the one call that must land."""
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _raise_if_failed(endpoint):
    assert endpoint["Status"] != "FAILED", (
        "the ACME endpoint entered FAILED and will never serve a directory: "
        f"{endpoint.get('FailureReason')!r}"
    )
    return False


def _active_endpoint(ctx, acm, *, contact="NOT_REQUIRED"):
    """Create an ACME endpoint in-check and return (arn, directory url) once ACTIVE."""
    arn = _retry_throttle(lambda: acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {
            "AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Contact=contact,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(acm, arn))
    endpoint = _poll_until(
        lambda: _retry_throttle(
            lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn))["AcmeEndpoint"],
        lambda ep: ep["Status"] == "ACTIVE" or _raise_if_failed(ep),
        timeout_s=240, interval_s=5,
        description="the ACME endpoint reaching ACTIVE",
    )
    return arn, endpoint["EndpointUrl"]


def _acme_role(ctx):
    """An IAM role ACM's ACME service can assume, created in-check (never named, never adopted
    from the account) so the check runs against an account that has nothing."""
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
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
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _external_account_binding(ctx, acm, endpoint_arn, role_arn):
    """CreateAcmeExternalAccountBinding, retried through IAM role propagation only."""
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


def _safe_delete_eab(acm, arn):
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arn)


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
        f"HEAD {new_nonce_url!r} must return a Replay-Nonce header; got {sorted(headers)}"
    )
    return nonce


def _account_key():
    """A fresh P-256 account key, generated in-process. It never leaves this process."""
    _hashes, ec, _decode = _crypto()
    return ec.generate_private_key(ec.SECP256R1())


def _jwk(private_key):
    """The RFC 7518 JWK for a P-256 public key, with members in the RFC 7638 canonical order."""
    numbers = private_key.public_key().public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _es256(private_key, protected_b64, payload_b64):
    """An ES256 (P-1363, r||s) signature over `protected.payload`, per RFC 7515/7518."""
    hashes, ec, decode_dss_signature = _crypto()
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _eab_jws(mac_key, key_id, new_account_url, jwk):
    """The inner HS256 JWS that binds an ACME account key to an external account (RFC 8555
    §7.3.4): protected = {alg, kid, url}, payload = the account key's JWK."""
    protected = _b64url(json.dumps(
        {"alg": "HS256", "kid": key_id, "url": new_account_url}).encode())
    payload = _b64url(json.dumps(jwk).encode())
    signature = _b64url(
        hmac.new(mac_key, f"{protected}.{payload}".encode(), hashlib.sha256).digest())
    return {"protected": protected, "payload": payload, "signature": signature}


def _post_new_account(ctx, new_account_url, nonce, key, payload_obj):
    """POST a flattened ES256 JWS to newAccount -> (status, headers, parsed-or-raw body)."""
    protected = _b64url(json.dumps(
        {"alg": "ES256", "jwk": _jwk(key), "nonce": nonce, "url": new_account_url}).encode())
    payload = _b64url(json.dumps(payload_obj).encode())
    body = json.dumps({
        "protected": protected,
        "payload": payload,
        "signature": _es256(key, protected, payload),
    }).encode()
    status, headers, raw = _http(ctx,
        new_account_url, data=body,
        headers={"Content-Type": "application/jose+json"}, method="POST")
    return status, headers, raw


def _problem(raw):
    """The RFC 7807 problem document in an ACME error body, or a loud failure."""
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
    """Every AccountUrl ACM has registered against an endpoint, following NextToken."""
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


# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A newAccount whose externalAccountBinding is HMAC'd with a forged key of the right length
    is refused with an ACME problem document and registers no account, while the same request
    signed with the real MacKey succeeds, so ACM verifies the EAB MAC (RFC 8555 7.3.4).
    Reference: https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-endpoints.html
    """
    acm = ctx.client("acm")
    endpoint_arn, directory_url = _active_endpoint(ctx, acm)
    role_arn = _acme_role(ctx)
    eab_arn = _external_account_binding(ctx, acm, endpoint_arn, role_arn)

    credentials = _retry_throttle(lambda: acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn))
    key_id = credentials["KeyId"]
    real_mac = _b64url_decode(credentials["MacKey"])
    assert real_mac, "GetAcmeExternalAccountBindingCredentials returned an empty MacKey"

    directory = _directory(ctx, directory_url)
    new_account_url = directory["newAccount"]
    new_nonce_url = directory["newNonce"]

    # --- beat 1: positive control. The real MacKey registers an account. ---
    control_key = _account_key()
    started = time.monotonic()
    status, headers, raw = _post_new_account(ctx,
        new_account_url, _fresh_nonce(ctx, new_nonce_url), control_key,
        {"termsOfServiceAgreed": True,
         "externalAccountBinding": _eab_jws(
             real_mac, key_id, new_account_url, _jwk(control_key))},
    )
    assert status in (200, 201), (
        f"a newAccount signed with the real MacKey must be accepted; got HTTP {status} "
        f"{raw[:300]!r}"
    )
    control_url = headers.get("location", "")
    assert control_url, (
        f"RFC 8555 §7.3 requires a Location header naming the created account; headers were "
        f"{sorted(headers)}"
    )

    described = _poll_until(
        lambda: _retry_throttle(lambda: acm.describe_acme_account(
            AcmeEndpointArn=endpoint_arn, AccountUrl=control_url))["AcmeAccount"],
        lambda account: account["Status"] == "VALID",
        timeout_s=60, interval_s=3,
        description="ACM reporting the control account VALID",
    )
    assert described["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"the control account must be bound to the EAB that authorised it; ACM reports "
        f"{described['AcmeExternalAccountBindingArn']!r}, expected {eab_arn!r}"
    )
    listable = _poll_until(
        lambda: _account_urls(acm, endpoint_arn),
        lambda urls: control_url in urls,
        timeout_s=60, interval_s=3,
        description="the control account appearing in ListAcmeAccounts",
    )
    # L: the control's own end-to-end latency from POST to listable, on this exact wiring.
    # The absence below is held for 3L, so a correct-but-slower target is never scored as
    # having blocked.
    control_latency = time.monotonic() - started
    assert listable == {control_url}, (
        f"the endpoint was created by this check, so its account registry must hold exactly "
        f"the control account; got {sorted(listable)}"
    )

    # --- beat 2: break exactly ONE thing -- the MAC key, at the same length. ---
    forged_key = _account_key()
    forged_mac = os.urandom(len(real_mac))
    assert forged_mac != real_mac, "the forged MacKey collided with the real one"
    status, forged_headers, raw = _post_new_account(ctx,
        new_account_url, _fresh_nonce(ctx, new_nonce_url), forged_key,
        {"termsOfServiceAgreed": True,
         "externalAccountBinding": _eab_jws(
             forged_mac, key_id, new_account_url, _jwk(forged_key))},
    )

    # --- beat 3: the specific refusal. ---
    assert status != 200 and status != 201, (
        f"a newAccount whose externalAccountBinding is HMAC'd with a key ACM never issued must "
        f"be refused; it returned HTTP {status} with Location "
        f"{forged_headers.get('location')!r}"
    )
    assert status == 403, (
        f"RFC 8555 §7.3.4's MAC-verification failure is expected as HTTP 403; got {status} "
        f"with body {raw[:200]!r}"
    )
    problem = _problem(raw)
    problem_type = problem.get("type", "<absent>")
    # (4a) structural: an ACME server signals errors as namespaced problem types.
    assert isinstance(problem_type, str) and problem_type.startswith(_ACME_ERROR_PREFIX), (
        f"an ACME refusal must carry an RFC 8555 §6.7 problem type under "
        f"{_ACME_ERROR_PREFIX!r}; got {problem_type!r} in {problem!r}"
    )
    # (4b) the exact type.
    assert problem_type == _EXPECTED_PROBLEM, (
        f"a forged external-account MAC must be refused as {_EXPECTED_PROBLEM!r}; got "
        f"{problem_type!r} (detail {problem.get('detail')!r})"
    )

    # --- beat 4: the effect is ABSENT, at the producer's own registry, for 3L. ---
    absence_window = max(3 * control_latency, 15.0)
    absence_deadline = time.monotonic() + absence_window
    while time.monotonic() < absence_deadline:
        urls = _account_urls(acm, endpoint_arn)
        assert urls == {control_url}, (
            f"the refused registration created an account anyway: ListAcmeAccounts holds "
            f"{sorted(urls)}, expected only the control {control_url!r} "
            f"(watched for {absence_window:.1f}s = 3x the control's own {control_latency:.1f}s)"
        )
        time.sleep(3)
    # Second independent observable of the same absence: the forged key's own account URL, had
    # one been minted, would be the value of the Location header. There is none.
    assert not forged_headers.get("location"), (
        f"the refused registration returned a Location header "
        f"{forged_headers.get('location')!r}, so something WAS created"
    )

    # --- beat 5 + 6: restore the real MacKey; the identical call now succeeds. ---
    restored_key = _account_key()
    status, headers, raw = _post_new_account(ctx,
        new_account_url, _fresh_nonce(ctx, new_nonce_url), restored_key,
        {"termsOfServiceAgreed": True,
         "externalAccountBinding": _eab_jws(
             real_mac, key_id, new_account_url, _jwk(restored_key))},
    )
    assert status in (200, 201), (
        f"restoring the real MacKey must make the identical registration succeed again; got "
        f"HTTP {status} {raw[:300]!r}"
    )
    restored_url = headers.get("location", "")
    assert restored_url and restored_url != control_url, (
        f"the restored registration must mint a NEW account (a new account key); Location was "
        f"{restored_url!r} and the control's was {control_url!r}"
    )

    # Terminal read: at the destination, through ListAcmeAccounts -- a different operation than
    # the HTTPS POST that mutated, on the far side of the AWS/ACME boundary.
    final = _poll_until(
        lambda: _account_urls(acm, endpoint_arn),
        lambda urls: restored_url in urls,
        timeout_s=60, interval_s=3,
        description="the restored account appearing in ListAcmeAccounts",
    )
    assert final == {control_url, restored_url}, (
        f"the endpoint must hold exactly the two accounts that were accepted and none that "
        f"were refused; got {sorted(final)}, expected "
        f"{sorted({control_url, restored_url})}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
