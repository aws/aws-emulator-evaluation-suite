"""acme-account-identity-is-the-account-key-not-the-binding."""
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


CHECK = "acme-account-identity-is-the-account-key-not-the-binding"
GROUP = "state-machine"
SERVICES = ["acm"]

_ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:"
_ACCOUNT_DOES_NOT_EXIST = _ACME_ERROR_PREFIX + "accountDoesNotExist"

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
    """The RFC 7518 JWK for a P-256 public key. Members are the RFC 7638 REQUIRED set for
    `kty: EC`, in lexicographic order, so this dict is already the canonical thumbprint input."""
    numbers = private_key.public_key().public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _jwk_thumbprint_digest(jwk):
    """The raw RFC 7638 JWK thumbprint DIGEST of a P-256 public JWK.

    RFC 7638 §3.1: construct a JSON object with only the required members for the key type, in
    lexicographic order, with no whitespace, then SHA-256 it. Recomputed here from the key this
    process generated, so the expected value follows the key and not a fixed string.
    """
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).digest()


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


# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ACME account's identity is its account key (RFC 8555 7.3): re-registering the same key
    returns the same account, PublicKeyThumbprint is the RFC 7638 thumbprint of that key, and
    onlyReturnExisting fails with accountDoesNotExist for an unknown key but resolves a known one.
    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_AcmeAccount.html
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

    # --- beat 1: register account key K. ---
    key_k = _account_key()
    jwk_k = _jwk(key_k)
    status, headers, raw = _post_new_account(ctx,
        new_account_url, _fresh_nonce(ctx, new_nonce_url), key_k,
        {"termsOfServiceAgreed": True,
         "externalAccountBinding": _eab_jws(mac_key, key_id, new_account_url, jwk_k)},
    )
    assert status in (200, 201), (
        f"the first newAccount for key K must be accepted; got HTTP {status} {raw[:300]!r}")
    url_k = headers.get("location", "")
    assert url_k, (
        f"RFC 8555 §7.3 requires a Location header naming the created account; headers were "
        f"{sorted(headers)}"
    )
    described = _poll_until(
        lambda: _retry_throttle(lambda: acm.describe_acme_account(
            AcmeEndpointArn=endpoint_arn, AccountUrl=url_k))["AcmeAccount"],
        lambda account: account["Status"] == "VALID",
        timeout_s=60, interval_s=3,
        description="ACM reporting account K VALID",
    )
    assert described["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"account K must be bound to the EAB that authorised it; ACM reports "
        f"{described['AcmeExternalAccountBindingArn']!r}, expected {eab_arn!r}"
    )

    # --- beat 2: the thumbprint is the RFC 7638 digest of K, recomputed here. ---
    digest = _jwk_thumbprint_digest(jwk_k)
    acceptable = {_b64url(digest), digest.hex()}
    reported = described.get("PublicKeyThumbprint", "<absent>")
    assert reported in acceptable, (
        f"PublicKeyThumbprint must be the RFC 7638 thumbprint of the ACME account key. ACM "
        f"reports {reported!r}; the key this check generated hashes to "
        f"{_b64url(digest)!r} (base64url) / {digest.hex()!r} (hex)"
    )

    # --- beat 3: the SAME key re-POSTed returns the SAME account, not a second one. ---
    status, headers, raw = _post_new_account(ctx,
        new_account_url, _fresh_nonce(ctx, new_nonce_url), key_k,
        {"termsOfServiceAgreed": True,
         "externalAccountBinding": _eab_jws(mac_key, key_id, new_account_url, jwk_k)},
    )
    assert status == 200, (
        f"RFC 8555 §7.3: a newAccount signed with an already-registered key MUST answer 200, "
        f"distinguishing 'here is your existing account' from 201 'created'; got {status} with "
        f"body {raw[:200]!r}"
    )
    assert headers.get("location", "") == url_k, (
        f"re-POSTing the same account key must return the SAME account URL; got "
        f"{headers.get('location')!r}, expected {url_k!r} -- an implementation that mints a new "
        f"account here forks a client's identity on every restart"
    )

    # --- beat 4: onlyReturnExisting for a key that was never registered. ---
    key_f = _account_key()
    status, fresh_headers, raw = _post_new_account(ctx,
        new_account_url, _fresh_nonce(ctx, new_nonce_url), key_f, {"onlyReturnExisting": True})
    assert status not in (200, 201), (
        f"onlyReturnExisting must not CREATE an account for an unregistered key; ACM answered "
        f"HTTP {status} with Location {fresh_headers.get('location')!r}"
    )
    assert status == 400, (
        f"RFC 8555 §7.3.1 requires HTTP 400 when onlyReturnExisting finds no account; got "
        f"{status} with body {raw[:200]!r}"
    )
    problem = _problem(raw)
    problem_type = problem.get("type", "<absent>")
    assert isinstance(problem_type, str) and problem_type.startswith(_ACME_ERROR_PREFIX), (
        f"an ACME refusal must carry an RFC 8555 §6.7 problem type under "
        f"{_ACME_ERROR_PREFIX!r}; got {problem_type!r} in {problem!r}"
    )
    assert problem_type == _ACCOUNT_DOES_NOT_EXIST, (
        f"onlyReturnExisting for an unknown key must be refused as "
        f"{_ACCOUNT_DOES_NOT_EXIST!r}; got {problem_type!r} (detail "
        f"{problem.get('detail')!r})"
    )
    assert not fresh_headers.get("location"), (
        f"the refused lookup returned a Location header {fresh_headers.get('location')!r}, so "
        f"an account WAS created for a key that only asked whether one existed"
    )

    # --- beat 5: the positive control for beat 4 -- the KNOWN key resolves. ---
    status, headers, raw = _post_new_account(ctx,
        new_account_url, _fresh_nonce(ctx, new_nonce_url), key_k, {"onlyReturnExisting": True})
    assert status == 200, (
        f"onlyReturnExisting for a registered key must answer 200 and resolve the account; got "
        f"HTTP {status} {raw[:300]!r} -- without this leg, beat 4 cannot tell "
        f"'refuses an unknown key' from 'refuses every lookup'"
    )
    assert headers.get("location", "") == url_k, (
        f"onlyReturnExisting must resolve key K to its own account {url_k!r}; got "
        f"{headers.get('location')!r}"
    )

    # --- beat 6: terminal read at the destination -- four POSTs, exactly one account. ---
    final = _account_urls(acm, endpoint_arn)
    assert final == {url_k}, (
        f"this check created the endpoint, made four newAccount POSTs and only ONE of them was "
        f"a registration of a new key, so ACM must hold exactly {url_k!r}; ListAcmeAccounts "
        f"holds {sorted(final)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
