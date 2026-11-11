"""concurrent-revoke-acme-account-single-winner."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "concurrent-revoke-acme-account-single-winner"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Two concurrent RevokeAcmeAccount calls on one ACME account both succeed idempotently, the
    account converges to REVOKED, and a further revoke also succeeds and leaves it REVOKED."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx)
    eab_arn = _create_eab(ctx, acm, endpoint_arn, role_arn)
    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    key_id, mac_key = creds["KeyId"], creds["MacKey"]

    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"][
        "EndpointUrl"
    ]
    account_url = _register_acme_account(ctx, endpoint_url, key_id, mac_key)

    def _revoke():
        return acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    results = _race([_revoke, _revoke])
    codes = [code for _, code in results]
    successes = [r for r, code in results if code is None]
    assert len(successes) == 2, (
        f"expected RevokeAcmeAccount to be idempotent under a concurrent race (both "
        f"calls succeed, no ConflictException), got results={results}"
    )
    assert codes.count("ConflictException") == 0, (
        f"expected no ConflictException from either racer, got codes={codes}"
    )

    final_status = acm.describe_acme_account(
        AcmeEndpointArn=endpoint_arn, AccountUrl=account_url
    )["AcmeAccount"]["Status"]
    assert final_status == "REVOKED", f"expected REVOKED after the race, got {final_status}"

    # No double-revocation side effect: a further revoke of the already-revoked
    # account is itself an idempotent success that leaves the
    # terminal state unchanged, not a conflict. Any error the call raises propagates and
    # fails the check.
    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    after_status = acm.describe_acme_account(
        AcmeEndpointArn=endpoint_arn, AccountUrl=account_url
    )["AcmeAccount"]["Status"]
    assert after_status == "REVOKED", "idempotent re-revoke must leave account state unchanged"


def _race(fns):
    out = [None] * len(fns)

    def _wrap(i, fn):
        try:
            out[i] = (fn(), None)
        except ClientError as exc:
            out[i] = (None, exc.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for f in futures:
            f.result()
    return out


def _wait_endpoint_active(acm, arn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError("ACME endpoint creation failed")
        time.sleep(interval_s)
    raise AssertionError("ACME endpoint never became ACTIVE within timeout")


def _create_active_endpoint(ctx, acm):
    name = ctx.unique_name("sim2real-acm-acme-endpoint-")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": name}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_endpoint_active(acm, arn)
    return arn


def _create_eab_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acm-acme-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


def _create_eab(ctx, acm, endpoint_arn, role_arn):
    # iam:PassRole against a just-created role is eventually consistent: the caller
    # identity can see AccessDeniedException for several seconds after create_role
    # returns, so the create is retried to a deadline.
    name = ctx.unique_name("sim2real-acm-eab-")
    deadline = time.monotonic() + 40.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            eab_arn = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn, Tags=[{"Key": "Name", "Value": name}]
            )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(
                lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
            )
            return eab_arn
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"role {role_arn} never became usable for EAB creation: {last_err}")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode_any(s: str) -> bytes:
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    return base64.b64decode(s2)


def _http(ctx, url, data=None, headers=None, method=None):
    req = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def _register_acme_account(ctx, directory_url, key_id, mac_key):
    """Minimal RFC 8555 account registration (newAccount with external account
    binding) implemented directly over stdlib HTTP + cryptography JWS signing, so
    this check exercises the endpoint's real native ACME protocol without depending
    on the 'acme'/'josepy' PyPI packages."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    status, _, body = _http(ctx, directory_url)
    if status != 200:
        raise AssertionError(f"ACME directory fetch failed: {status} {body!r}")
    directory = json.loads(body)

    status, headers, _ = _http(ctx, directory["newNonce"], method="HEAD")
    nonce = headers.get("replay-nonce")
    if not nonce:
        status, headers, _ = _http(ctx, directory["newNonce"], method="GET")
        nonce = headers.get("replay-nonce")
    if not nonce:
        raise AssertionError("ACME server did not return a Replay-Nonce")

    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }
    new_account_url = directory["newAccount"]

    eab_mac_key = _b64decode_any(mac_key)
    eab_protected = _b64url(json.dumps({"alg": "HS256", "kid": key_id, "url": new_account_url}).encode())
    eab_payload = _b64url(json.dumps(jwk).encode())
    eab_sig = _b64url(hmac.new(eab_mac_key, f"{eab_protected}.{eab_payload}".encode(), hashlib.sha256).digest())
    eab_jws = {"protected": eab_protected, "payload": eab_payload, "signature": eab_sig}

    outer_protected = _b64url(
        json.dumps({"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": new_account_url}).encode()
    )
    outer_payload = _b64url(
        json.dumps({"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}).encode()
    )
    signing_input = f"{outer_protected}.{outer_payload}".encode()
    der_sig = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    outer_sig = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    body_obj = json.dumps(
        {"protected": outer_protected, "payload": outer_payload, "signature": outer_sig}
    ).encode()
    status, headers, resp_body = _http(ctx,
        new_account_url, data=body_obj, headers={"Content-Type": "application/jose+json"}, method="POST"
    )
    if status not in (200, 201):
        raise AssertionError(f"ACME newAccount failed: {status} {resp_body!r}")
    account_url = headers.get("location")
    if not account_url:
        raise AssertionError("ACME newAccount response missing Location header")
    return account_url


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
