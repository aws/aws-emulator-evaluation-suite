"""revoke-already-revoked-acme-account-is-idempotent."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "revoke-already-revoked-acme-account-is-idempotent"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Calling RevokeAcmeAccount a second time on an already-revoked account
    succeeds idempotently rather than raising ConflictException. The redundant
    call has no destructive side effect: the account remains REVOKED.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx)
    role_arn = _create_eab_role(ctx)

    eab_arn = _create_eab(ctx, endpoint_arn, role_arn)

    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    key_id, mac_key_raw = creds["KeyId"], creds["MacKey"]

    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["EndpointUrl"]

    try:
        account_url = _register_acme_account(ctx, endpoint_url, key_id, mac_key_raw, ec, hashes, decode_dss_signature)
    except Exception as exc:  # pragma: no cover - external protocol/network dependency
        raise AssertionError(f"ACME protocol account registration did not complete: {exc!r}")

    ctx.on_cleanup(
        lambda: _ignore(lambda: acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url))
    )

    described = _poll_until(
        lambda: acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"],
        lambda a: a["Status"] == "VALID",
        timeout_s=20,
        interval_s=2,
    )
    assert described["Status"] == "VALID", f"expected freshly-registered account VALID, got {described['Status']}"
    assert described["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"expected registered account's EAB arn to be {eab_arn!r}, got {described['AcmeExternalAccountBindingArn']!r}"
    )

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
    after_first = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert after_first["Status"] == "REVOKED", f"expected REVOKED after first revoke, got {after_first['Status']}"

    # The redundant revoke succeeds (idempotent, no ConflictException) -- what
    # matters is that it has no destructive side effect on already-REVOKED state.
    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    after_second = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert after_second["Status"] == "REVOKED", "account status must remain REVOKED after the redundant re-revoke"


def _ignore(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_active_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    if status != "ACTIVE":
        raise AssertionError(
            f"ACME endpoint did not become ACTIVE (status={status})",
        )
    return arn


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-acme-eab-role-")
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
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore(lambda: iam.delete_role(RoleName=name)))
    return role_arn


def _create_eab(ctx, endpoint_arn: str, role_arn: str) -> str:
    """Creates the EAB, retrying while ACM reports the just-created role as not yet
    assumable -- IAM trust-policy propagation is eventually consistent, so this is a
    bounded wait for that specific condition rather than a fixed sleep."""
    acm = ctx.client("acm")
    last_err: ClientError | None = None
    for _ in range(12):
        try:
            resp = acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
            eab_arn = resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(
                lambda a=eab_arn: _ignore(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=a))
            )
            return eab_arn
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create EAB after IAM role propagation retries: {last_err!r}")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _flexible_b64decode(value: str) -> bytes:
    stripped = value.strip()
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded)
    except Exception:
        urlsafe = padded.replace("-", "+").replace("_", "/")
        return base64.b64decode(urlsafe)


def _register_acme_account(ctx, endpoint_url: str, key_id: str, mac_key_raw: str, ec, hashes, decode_dss_signature) -> str:
    """Performs a minimal RFC 8555 account registration with an external account
    binding against a real ACM ACME directory URL, returning the account URL."""
    common_headers = {"User-Agent": "sim2real-acm-acme-check/1.0"}

    dir_req = _routed_request(ctx, endpoint_url, headers={**common_headers, "Accept": "application/json"})
    with urllib.request.urlopen(dir_req, timeout=20) as resp:
        directory = json.loads(resp.read().decode())
    new_nonce_url = directory["newNonce"]
    new_account_url = directory["newAccount"]

    nonce_req = _routed_request(ctx, new_nonce_url, method="HEAD", headers=common_headers)
    with urllib.request.urlopen(nonce_req, timeout=20) as resp:
        nonce = resp.headers.get("Replay-Nonce")
    if not nonce:
        raise RuntimeError("ACME directory did not return a Replay-Nonce")

    account_key = ec.generate_private_key(ec.SECP256R1())
    numbers = account_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }

    inner_protected = {"alg": "HS256", "kid": key_id, "url": new_account_url}
    inner_protected_b64 = _b64url(json.dumps(inner_protected, separators=(",", ":")).encode())
    inner_payload_b64 = _b64url(json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode())
    mac_key = _flexible_b64decode(mac_key_raw)
    inner_sig = hmac.new(
        mac_key, f"{inner_protected_b64}.{inner_payload_b64}".encode(), hashlib.sha256
    ).digest()
    eab_jws = {
        "protected": inner_protected_b64,
        "payload": inner_payload_b64,
        "signature": _b64url(inner_sig),
    }

    outer_protected = {"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": new_account_url}
    outer_payload = {"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}
    outer_protected_b64 = _b64url(json.dumps(outer_protected, separators=(",", ":")).encode())
    outer_payload_b64 = _b64url(json.dumps(outer_payload, separators=(",", ":")).encode())
    signing_input = f"{outer_protected_b64}.{outer_payload_b64}".encode()
    der_sig = account_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    outer_jws = {
        "protected": outer_protected_b64,
        "payload": outer_payload_b64,
        "signature": _b64url(raw_sig),
    }

    body = json.dumps(outer_jws).encode()
    post_req = _routed_request(ctx,
        new_account_url,
        data=body,
        method="POST",
        headers={**common_headers, "Content-Type": "application/jose+json"},
    )
    try:
        with urllib.request.urlopen(post_req, timeout=20) as resp:
            if resp.status not in (200, 201):
                raise RuntimeError(f"unexpected newAccount HTTP status {resp.status}")
            account_url = resp.headers.get("Location")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"newAccount request failed: HTTP {exc.code} {detail}") from exc

    if not account_url:
        raise RuntimeError("newAccount response did not include a Location header")
    return account_url


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
