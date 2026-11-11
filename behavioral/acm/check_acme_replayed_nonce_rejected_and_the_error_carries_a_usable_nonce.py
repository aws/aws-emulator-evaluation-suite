"""acme-replayed-nonce-rejected-and-the-error-carries-a-usable-nonce."""
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


CHECK = "acme-replayed-nonce-rejected-and-the-error-carries-a-usable-nonce"
GROUP = "overly-permissive"
SERVICES = ["acm"]

_ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:"
_BAD_NONCE = _ACME_ERROR_PREFIX + "badNonce"

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
    """One HTTP round trip -> (status, lower-cased headers, body). HTTP error STATUS is a value
    this check grades; a transport failure is not caught."""
    request = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return (response.status,
                    {k.lower(): v for k, v in response.headers.items()},
                    response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _safe_delete_endpoint(acm, arn):
    """Teardown. Deleting the endpoint cascades its EABs and registered accounts."""
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _safe_delete_eab(acm, arn):
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arn)


def _raise_if_failed(endpoint):
    assert endpoint["Status"] != "FAILED", (
        "the ACME endpoint entered FAILED and will never serve a directory: "
        f"{endpoint.get('FailureReason')!r}"
    )
    return False


def _active_endpoint(ctx, acm):
    arn = _retry_throttle(lambda: acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {
            "AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Contact="NOT_REQUIRED",
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
    """POST a flattened ES256 JWS to newAccount -> (status, headers, raw body)."""
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



@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A spent ACME nonce is refused with HTTP 400 badNonce and registers no account, and the fresh
    Replay-Nonce on that error response is accepted for the identical request (RFC 8555 6.5).

    Reference: https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-endpoints.html
    """
    acm = ctx.client("acm")
    endpoint_arn, directory_url = _active_endpoint(ctx, acm)
    role_arn = _acme_role(ctx)
    eab_arn = _external_account_binding(ctx, acm, endpoint_arn, role_arn)

    credentials = _retry_throttle(lambda: acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn))
    key_id = credentials["KeyId"]
    mac_key = _b64url_decode(credentials["MacKey"])
    assert mac_key, "GetAcmeExternalAccountBindingCredentials returned an empty MacKey"

    directory = _directory(ctx, directory_url)
    new_account_url = directory["newAccount"]
    new_nonce_url = directory["newNonce"]

    # --- beat 1: positive control -- a fresh nonce registers account A. ---
    nonce = _fresh_nonce(ctx, new_nonce_url)
    key_a = _account_key()
    started = time.monotonic()
    status, headers, raw = _post_new_account(ctx,
        new_account_url, nonce, key_a,
        {"termsOfServiceAgreed": True,
         "externalAccountBinding": _eab_jws(mac_key, key_id, new_account_url, _jwk(key_a))},
    )
    assert status in (200, 201), (
        f"a newAccount with a fresh nonce must be accepted; got HTTP {status} {raw[:300]!r}")
    url_a = headers.get("location", "")
    assert url_a, (
        f"RFC 8555 §7.3 requires a Location header naming the created account; headers were "
        f"{sorted(headers)}"
    )
    _poll_until(
        lambda: _account_urls(acm, endpoint_arn),
        lambda urls: url_a in urls,
        timeout_s=60, interval_s=3,
        description="account A appearing in ListAcmeAccounts",
    )
    # L, measured on this exact wiring in this run: POST -> listable at ACM.
    control_latency = time.monotonic() - started

    # --- beat 2: break exactly ONE thing -- replay the spent nonce, for a new key. ---
    key_b = _account_key()
    payload_b = {
        "termsOfServiceAgreed": True,
        "externalAccountBinding": _eab_jws(mac_key, key_id, new_account_url, _jwk(key_b)),
    }
    status, replay_headers, raw = _post_new_account(ctx,
        new_account_url, nonce, key_b, payload_b)

    # --- beat 3: the specific refusal. ---
    assert status not in (200, 201), (
        f"replaying an already-spent nonce must not register an account; ACM answered HTTP "
        f"{status} with Location {replay_headers.get('location')!r}"
    )
    assert status == 400, (
        f"RFC 8555 §6.5 requires HTTP 400 for an unacceptable nonce; got {status} with body "
        f"{raw[:200]!r}"
    )
    problem = _problem(raw)
    problem_type = problem.get("type", "<absent>")
    assert isinstance(problem_type, str) and problem_type.startswith(_ACME_ERROR_PREFIX), (
        f"an ACME refusal must carry an RFC 8555 §6.7 problem type under "
        f"{_ACME_ERROR_PREFIX!r}; got {problem_type!r} in {problem!r}"
    )
    assert problem_type == _BAD_NONCE, (
        f"a replayed nonce must be refused as {_BAD_NONCE!r}; got {problem_type!r} "
        f"(detail {problem.get('detail')!r})"
    )

    # --- beat 4: the effect is ABSENT, at ACM's own registry, for 3L. ---
    assert not replay_headers.get("location"), (
        f"the refused replay returned a Location header {replay_headers.get('location')!r}, so "
        f"an account WAS created"
    )
    absence_window = max(3 * control_latency, 15.0)
    absence_deadline = time.monotonic() + absence_window
    while time.monotonic() < absence_deadline:
        urls = _account_urls(acm, endpoint_arn)
        assert urls == {url_a}, (
            f"the replayed-nonce request registered an account anyway: ListAcmeAccounts holds "
            f"{sorted(urls)}, expected only {url_a!r} (watched {absence_window:.1f}s = 3x the "
            f"control's own {control_latency:.1f}s to become listable)"
        )
        time.sleep(3)

    # --- beat 5: RFC 8555 §6.5's promise -- the ERROR carried a nonce the server accepts. ---
    supplied_nonce = replay_headers.get("replay-nonce", "")
    assert supplied_nonce, (
        f"RFC 8555 §6.5 requires a badNonce response to include a Replay-Nonce header with a "
        f"fresh nonce; the error carried headers {sorted(replay_headers)} and no nonce, which "
        f"leaves every conforming client permanently wedged"
    )
    assert supplied_nonce != nonce, (
        f"the badNonce response handed back the very nonce it just rejected ({nonce!r}); the "
        f"RFC requires a FRESH one"
    )

    # --- beat 6: the identical request, with only that nonce changed, now succeeds. ---
    status, headers, raw = _post_new_account(ctx,
        new_account_url, supplied_nonce, key_b, payload_b)
    assert status in (200, 201), (
        f"the nonce supplied on the badNonce error must be accepted (RFC 8555 §6.5: \"a fresh "
        f"nonce that the server will accept\"); the identical request answered HTTP {status} "
        f"{raw[:300]!r}"
    )
    url_b = headers.get("location", "")
    assert url_b and url_b != url_a, (
        f"the retried registration must mint a distinct account; Location was {url_b!r} and "
        f"account A's was {url_a!r}"
    )

    # Terminal read at the destination, via a different operation than the HTTPS POST: ACM's
    # own account registry holds exactly the two accepted registrations.
    final = _poll_until(
        lambda: _account_urls(acm, endpoint_arn),
        lambda urls: url_b in urls,
        timeout_s=60, interval_s=3,
        description="account B appearing in ListAcmeAccounts after the accepted retry",
    )
    assert final == {url_a, url_b}, (
        f"ACM must hold exactly the two accepted accounts and nothing from the refused replay; "
        f"got {sorted(final)}, expected {sorted({url_a, url_b})}"
    )
    described = _retry_throttle(lambda: acm.describe_acme_account(
        AcmeEndpointArn=endpoint_arn, AccountUrl=url_b))["AcmeAccount"]
    assert described["Status"] == "VALID", (
        f"the account created by the retried request must be VALID; ACM reports "
        f"{described['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
