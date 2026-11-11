"""revoke-acme-account-sets-terminal-state."""
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


CHECK = "revoke-acme-account-sets-terminal-state"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """RevokeAcmeAccount moves an ACME account registered over the ACME protocol from VALID to a
    describable REVOKED state; a second revoke succeeds and the account stays REVOKED."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    iam = ctx.client("iam")

    endpoint_arn = _create_active_endpoint(ctx, acm, contact="NOT_REQUIRED")
    role_arn = _create_eab_role(ctx, iam)

    eab_arn = _create_eab_binding_with_retry(acm, endpoint_arn, role_arn)
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))
    )

    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["EndpointUrl"]

    account_url = _acme_register_account(ctx, endpoint_url, creds["KeyId"], creds["MacKey"])

    account = _wait_for_account_status(acm, endpoint_arn, account_url, {"VALID", "REVOKED"})
    assert account["Status"] == "VALID", f"unexpected initial ACME account status: {account['Status']}"

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
    account = _wait_for_account_status(acm, endpoint_arn, account_url, {"REVOKED"})
    assert account["Status"] == "REVOKED", f"expected REVOKED after revoke, got {account['Status']}"

    # Revoking an already-revoked account succeeds and leaves the terminal state as it is.
    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
    still = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert still["Status"] == "REVOKED", f"expected terminal REVOKED to hold after redundant double revoke, got {still['Status']}"


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _create_eab_role(ctx, iam) -> str:
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
    role_name = ctx.unique_name("sim2real-acme-eab-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_eab_binding_with_retry(
    acm, endpoint_arn: str, role_arn: str, timeout_s: float = 40.0, interval_s: float = 3.0
) -> str:
    """Retries CreateAcmeExternalAccountBinding to absorb IAM eventual-consistency
    propagation lag between iam.create_role and ACM's cross-service reference to that role."""
    deadline = time.monotonic() + timeout_s
    last_error: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
            )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
        except ClientError as exc:
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"create_acme_external_account_binding never resolved freshly created role "
        f"{role_arn} within {timeout_s}s: {last_error}"
    )


def _wait_for_account_status(acm, endpoint_arn: str, account_url: str, target_statuses: set, timeout_s: float = 30.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
        if last["Status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"ACME account never reached {target_statuses}, last={last}")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _http(ctx, url: str, *, data: bytes | None = None, headers: dict | None = None, method: str = "GET"):
    req = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


def _acme_register_account(ctx, endpoint_url: str, key_id: str, mac_key_b64url: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    status, _, body = _http(ctx, endpoint_url, method="GET")
    assert status == 200, f"ACME directory fetch failed: {status} {body!r}"
    directory = json.loads(body)
    new_account_url = directory["newAccount"]
    new_nonce_url = directory["newNonce"]

    status, headers, body = _http(ctx, new_nonce_url, method="HEAD")
    nonce = headers.get("Replay-Nonce")
    if not nonce:
        status, headers, body = _http(ctx, new_nonce_url, method="GET")
        nonce = headers.get("Replay-Nonce")
    assert nonce, f"no Replay-Nonce returned from newNonce (status={status})"

    private_key = ec.generate_private_key(ec.SECP256R1())
    nums = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(_int_to_bytes(nums.x, 32)),
        "y": _b64url(_int_to_bytes(nums.y, 32)),
    }

    mac_key = _b64url_decode(mac_key_b64url)
    eab_protected_b64 = _b64url(
        json.dumps({"alg": "HS256", "kid": key_id, "url": new_account_url}, separators=(",", ":")).encode()
    )
    eab_payload_b64 = _b64url(json.dumps(jwk, separators=(",", ":")).encode())
    eab_sig = hmac.new(mac_key, f"{eab_protected_b64}.{eab_payload_b64}".encode(), hashlib.sha256).digest()
    eab_jws = {"protected": eab_protected_b64, "payload": eab_payload_b64, "signature": _b64url(eab_sig)}

    payload = {"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    protected = {"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": new_account_url}
    protected_b64 = _b64url(json.dumps(protected, separators=(",", ":")).encode())
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    signature = _int_to_bytes(r, 32) + _int_to_bytes(s, 32)

    body_bytes = json.dumps(
        {"protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature)}
    ).encode()
    status, headers, resp_body = _http(ctx,
        new_account_url, data=body_bytes, headers={"Content-Type": "application/jose+json"}, method="POST"
    )
    assert status in (200, 201), f"ACME NewAccount failed: {status} {resp_body!r}"
    account_url = headers.get("Location")
    assert account_url, "ACME NewAccount response missing Location header"
    return account_url


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
