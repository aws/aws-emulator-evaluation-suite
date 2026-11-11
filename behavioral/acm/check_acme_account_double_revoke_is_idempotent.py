"""acme-account-double-revoke-is-idempotent."""
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


CHECK = "acme-account-double-revoke-is-idempotent"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """RevokeAcmeAccount on an already-REVOKED account succeeds again rather than
    raising ConflictException, and leaves the account's terminal state unchanged."""
    acm = ctx.client("acm")
    endpoint_arn, endpoint_url = _create_active_endpoint(ctx)
    role_arn = _create_acme_role(ctx)
    eab_arn, _binding = _create_eab(ctx, endpoint_arn, role_arn)
    key_id, mac_key = _get_eab_credentials(ctx, eab_arn)

    account_url = _acme_register_account(ctx, endpoint_url, key_id, mac_key)

    # Positive control: the first revoke succeeds and transitions VALID -> REVOKED.
    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
    mid = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert mid["Status"] == "REVOKED", f"expected REVOKED after first revoke, got {mid['Status']}"

    # RevokeAcmeAccount is idempotent: revoking an already-revoked account succeeds
    # again rather than raising, and must not change the terminal state. Any error the
    # second call raises propagates and fails the check.
    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    after = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert after["Status"] == "REVOKED", "idempotent double-revoke must leave account state unchanged"


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


def _create_active_endpoint(ctx) -> tuple[str, str]:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(ctx, arn))
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        ep = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if ep["Status"] == "ACTIVE":
            return arn, ep["EndpointUrl"]
        if ep["Status"] == "FAILED":
            raise AssertionError(f"ACME endpoint entered FAILED: {ep.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(
        "ACME endpoint did not reach ACTIVE status within timeout",
    )


def _safe_delete_endpoint(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _create_acme_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "acme-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_eab(ctx, endpoint_arn: str, role_arn: str) -> tuple[str, dict[str, Any]]:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    last_err = None
    for _ in range(12):
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-eab-")}],
            )
            binding = resp["ExternalAccountBinding"]
            arn = binding["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(lambda a=arn: _safe_delete_eab(ctx, a))
            return arn, binding
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create EAB after IAM role propagation retries: {last_err}")


def _safe_delete_eab(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arn)


def _get_eab_credentials(ctx, eab_arn: str) -> tuple[str, str]:
    acm = ctx.client("acm")
    resp = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    return resp["KeyId"], resp["MacKey"]


def _acme_register_account(ctx, endpoint_url: str, eab_key_id: str, eab_mac_key: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    status, _, body = _http(ctx, endpoint_url)
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

    mac_key = _b64decode_any(eab_mac_key)
    eab_protected = _b64url(json.dumps({"alg": "HS256", "kid": eab_key_id, "url": new_account_url}).encode())
    eab_payload = _b64url(json.dumps(jwk).encode())
    eab_sig = _b64url(hmac.new(mac_key, f"{eab_protected}.{eab_payload}".encode(), hashlib.sha256).digest())
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
