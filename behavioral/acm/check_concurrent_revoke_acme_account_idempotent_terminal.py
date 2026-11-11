"""concurrent-revoke-acme-account-idempotent-terminal."""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_lib
import json
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "concurrent-revoke-acme-account-idempotent-terminal"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """Two concurrent RevokeAcmeAccount calls on an ACME account registered over RFC 8555 each
    succeed or raise ConflictException, and the account converges to a single REVOKED state."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    endpoint_arn = _create_endpoint(ctx)
    endpoint = _wait_for_endpoint_active(ctx, endpoint_arn)
    directory_url = endpoint["EndpointUrl"]

    role_arn = _create_eab_role(ctx)
    _wait_role_usable(ctx, endpoint_arn, role_arn)

    eab_resp = acm.create_acme_external_account_binding(
        AcmeEndpointArn=endpoint_arn,
        RoleArn=role_arn,
        IdempotencyToken=ctx.unique_name("sim2real-acm-eab-"),
    )
    eab_arn = eab_resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )
    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )

    try:
        account_url = _acme_register_account(ctx, directory_url, creds["KeyId"], creds["MacKey"])
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AssertionError(
            f"could not reach the ACME endpoint's native directory URL {directory_url} over "
            f"the network from this runner ({exc}); outbound HTTPS access to "
            "acm-acme-enroll.*.api.aws is required to exercise the real ACME account "
            "registration flow that this check depends on"
        ) from exc

    account = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)[
        "AcmeAccount"
    ]
    assert account["Status"] == "VALID", f"freshly registered account should be VALID, got {account['Status']}"

    def revoker(_: int) -> tuple[str, str | None]:
        try:
            acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
            return ("ok", None)
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(revoker, 0), pool.submit(revoker, 1)]]

    # Both racers may be accepted (revocation is idempotent), or one collides with the other's
    # in-flight revoke and is refused.
    refused = [(status, message) for status, message in outcomes if status != "ok"]
    if refused:
        assert len(refused) == 1, f"expected at most one refused revoke: {outcomes}"
        status, message = refused[0]
        assert status == "ConflictException", f"unexpected revoke refusal: {outcomes}"
        assert message == f"Concurrent modification of ACME account {account_url}. Please try again.", (
            f"unexpected ConflictException message: {message!r}"
        )

    final = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)[
        "AcmeAccount"
    ]
    assert final["Status"] == "REVOKED", f"account did not converge to a terminal REVOKED state: {final['Status']}"


def _create_endpoint(ctx: Any) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx: Any, arn: str, timeout_s: float = 180.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        status = endpoint["Status"]
        if status == "ACTIVE":
            return endpoint
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} failed: {endpoint.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint {arn} never became ACTIVE within {timeout_s}s")


_EAB_TRUST_POLICY = {
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

_EAB_PERMISSIONS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
            "Resource": "*",
        }
    ],
}


def _create_eab_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acm-eab-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_EAB_TRUST_POLICY)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="acm-acme-cert-ops",
        PolicyDocument=json.dumps(_EAB_PERMISSIONS_POLICY),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="acm-acme-cert-ops"))
    return role_arn


def _wait_role_usable(ctx: Any, endpoint_arn: str, role_arn: str, timeout_s: float = 90.0) -> None:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        probe_token = ctx.unique_name("sim2real-acm-eab-probe-")
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn, IdempotencyToken=probe_token
            )
            probe_arn = resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=probe_arn)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"role {role_arn} never became usable for EAB creation: {last_code}")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _acme_register_account(ctx, directory_url: str, eab_key_id: str, eab_mac_key: str) -> str:
    """Minimal RFC 8555 account registration (newAccount with external account
    binding) implemented directly over stdlib HTTP + cryptography JWS signing,
    so this check exercises the endpoint's real native ACME protocol rather
    than only the ACM control-plane API."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    tls_ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(
            _routed_request(ctx, directory_url, method="GET"), timeout=30, context=tls_ctx
        ) as resp:
            directory = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise AssertionError(f"GET {directory_url} failed: HTTP {exc.code} {exc.read()!r}") from exc

    new_account_url = directory["newAccount"]
    new_nonce_url = directory["newNonce"]

    def _fresh_nonce() -> str:
        try:
            with urllib.request.urlopen(
                _routed_request(ctx, new_nonce_url, method="HEAD"), timeout=30, context=tls_ctx
            ) as resp:
                return resp.headers["Replay-Nonce"]
        except urllib.error.HTTPError as exc:
            raise AssertionError(f"HEAD {new_nonce_url} failed: HTTP {exc.code}") from exc

    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }

    mac_key = _b64url_decode(eab_mac_key)
    eab_protected = _b64url(
        json.dumps({"alg": "HS256", "kid": eab_key_id, "url": new_account_url}).encode()
    )
    eab_payload = _b64url(json.dumps(jwk).encode())
    eab_signature = _b64url(
        hmac_lib.new(mac_key, f"{eab_protected}.{eab_payload}".encode(), hashlib.sha256).digest()
    )
    eab_jws = {"protected": eab_protected, "payload": eab_payload, "signature": eab_signature}

    payload_b64 = _b64url(
        json.dumps({"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}).encode()
    )
    protected = {"alg": "ES256", "jwk": jwk, "nonce": _fresh_nonce(), "url": new_account_url}
    protected_b64 = _b64url(json.dumps(protected).encode())
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    sig_b64 = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    body = json.dumps(
        {"protected": protected_b64, "payload": payload_b64, "signature": sig_b64}
    ).encode()
    req = _routed_request(ctx,
        new_account_url, data=body, method="POST", headers={"Content-Type": "application/jose+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=tls_ctx) as resp:
            if resp.status not in (200, 201):
                raise AssertionError(f"ACME newAccount returned unexpected HTTP {resp.status}")
            location = resp.headers.get("Location")
            if not location:
                raise AssertionError("ACME newAccount response had no Location (account URL) header")
            return location
    except urllib.error.HTTPError as exc:
        raise AssertionError(
            f"ACME newAccount to {new_account_url} failed: HTTP {exc.code} {exc.read()!r}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
