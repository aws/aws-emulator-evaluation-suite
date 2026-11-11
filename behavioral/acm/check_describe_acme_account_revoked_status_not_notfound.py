"""describe-acme-account-revoked-status-not-notfound."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from typing import Any


from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "describe-acme-account-revoked-status-not-notfound"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After RevokeAcmeAccount, DescribeAcmeAccount still succeeds and reports Status REVOKED instead
    of raising ResourceNotFoundException: revocation is a status transition, not a delete."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    role_arn = _create_eab_role(ctx)
    eab = _create_eab_with_role_propagation_retry(
        acm, AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
    )["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(
            AcmeExternalAccountBindingArn=eab_arn
        )
    )
    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)[
        "AcmeEndpoint"
    ]["EndpointUrl"]

    account_url = _register_acme_account(ctx, endpoint_url, creds["KeyId"], creds["MacKey"])

    described = acm.describe_acme_account(
        AcmeEndpointArn=endpoint_arn, AccountUrl=account_url
    )["AcmeAccount"]
    assert described["Status"] == "VALID", described

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    described_after = acm.describe_acme_account(
        AcmeEndpointArn=endpoint_arn, AccountUrl=account_url
    )["AcmeAccount"]
    assert described_after["Status"] == "REVOKED", described_after


def _create_eab_with_role_propagation_retry(acm, **kwargs):
    """CreateAcmeExternalAccountBinding, retried while IAM propagates a just-created role: until
    then AWS answers AccessDeniedException on iam:PassRole for it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")


def _wait_for_endpoint_terminal(
    ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> dict[str, Any]:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if endpoint["Status"] in ("ACTIVE", "FAILED"):
            if endpoint["Status"] != "ACTIVE":
                raise AssertionError(
                    f"endpoint entered FAILED: {endpoint.get('FailureReason')}"
                )
            return endpoint
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} stayed CREATING past {timeout_s}s")


def _create_acme_endpoint(ctx) -> str:
    acm = ctx.client("acm")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_for_endpoint_terminal(ctx, arn)
    return arn


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-eab-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession",
                    "sts:SetSourceIdentity",
                ],
                "Condition": {
                    "StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-acme-eab-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _jws(protected: dict, payload_bytes: bytes, sign_fn) -> dict:
    protected_b64 = _b64url(json.dumps(protected).encode())
    payload_b64 = _b64url(payload_bytes)
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    signature = sign_fn(signing_input)
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": _b64url(signature),
    }


def _register_acme_account(ctx, endpoint_url: str, key_id: str, mac_key_b64: str) -> str:
    """Performs a real RFC 8555 ACME account registration (newAccount with an
    externalAccountBinding) against the endpoint's live ACME directory and
    returns the server-assigned account URL."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    with urllib.request.urlopen(_routed_request(ctx, endpoint_url), timeout=30) as resp:
        directory = json.loads(resp.read())
    new_account_url = directory["newAccount"]
    new_nonce_url = directory["newNonce"]

    priv = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(pub_numbers.x.to_bytes(32, "big")),
        "y": _b64url(pub_numbers.y.to_bytes(32, "big")),
    }
    mac_key_bytes = _b64url_decode(mac_key_b64)

    eab_protected = {"alg": "HS256", "kid": key_id, "url": new_account_url}
    eab_jws = _jws(
        eab_protected,
        json.dumps(jwk).encode(),
        lambda data: hmac.new(mac_key_bytes, data, hashlib.sha256).digest(),
    )
    payload_bytes = json.dumps(
        {"termsOfServiceAgreed": True, "externalAccountBinding": eab_jws}
    ).encode()

    def _fetch_nonce() -> str:
        req = _routed_request(ctx, new_nonce_url, method="HEAD")
        with urllib.request.urlopen(req, timeout=30) as resp:
            nonce = resp.headers.get("Replay-Nonce")
        if not nonce:
            raise AssertionError("ACME server did not return a Replay-Nonce")
        return nonce

    def _sign_es256(data: bytes) -> bytes:
        der_sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    last_error_body: bytes | None = None
    for attempt in range(2):
        nonce = _fetch_nonce()
        outer_protected = {
            "alg": "ES256",
            "jwk": jwk,
            "nonce": nonce,
            "url": new_account_url,
        }
        body = json.dumps(_jws(outer_protected, payload_bytes, _sign_es256)).encode()
        req = _routed_request(ctx,
            new_account_url,
            data=body,
            headers={"Content-Type": "application/jose+json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                account_url = resp.headers.get("Location")
                if not account_url:
                    raise AssertionError(
                        "ACME newAccount response missing Location header"
                    )
                return account_url
        except urllib.error.HTTPError as exc:
            last_error_body = exc.read()
            if attempt == 0 and exc.code == 400 and b"badNonce" in last_error_body:
                continue
            raise AssertionError(
                f"ACME newAccount failed ({exc.code}): {last_error_body!r}"
            ) from exc
    raise AssertionError(f"ACME newAccount failed after retry: {last_error_body!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
