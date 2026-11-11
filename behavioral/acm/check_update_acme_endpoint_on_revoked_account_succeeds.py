"""update-acme-endpoint-on-revoked-account-succeeds."""
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


CHECK = "update-acme-endpoint-on-revoked-account-succeeds"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After RevokeAcmeAccount revokes the endpoint's only ACME account, UpdateAcmeEndpoint on it
    still succeeds and the new Contact takes effect while the account stays REVOKED; a fresh
    endpoint accepts the same update."""
    import cryptography  # noqa: F401


    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    endpoint_arn = _create_active_endpoint(ctx, acm, contact="NOT_REQUIRED")
    role_arn = _create_eab_role(ctx, iam)
    binder = _binding_client(ctx, iam, sts, [role_arn])

    eab_arn = _create_eab_with_retry(ctx, binder, endpoint_arn, role_arn)
    ctx.on_cleanup(
        lambda: _delete_if_present(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))
    )

    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    endpoint_url = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["EndpointUrl"]

    account_url = _acme_register_account(ctx, endpoint_url, creds["KeyId"], creds["MacKey"])
    account = _wait_for_account_status(acm, endpoint_arn, account_url, {"VALID", "REVOKED"})
    assert account["Status"] == "VALID", f"unexpected initial ACME account status: {account['Status']}"

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)
    account = _wait_for_account_status(acm, endpoint_arn, account_url, {"REVOKED"})
    assert account["Status"] == "REVOKED", f"expected REVOKED after RevokeAcmeAccount, got {account['Status']}"

    # No ConflictException: the endpoint's config is not gated by an ACME account's state.
    acm.update_acme_endpoint(AcmeEndpointArn=endpoint_arn, Contact="REQUIRED")

    described = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert described.get("Contact") == "REQUIRED", (
        f"UpdateAcmeEndpoint(Contact=REQUIRED) did not take effect, DescribeAcmeEndpoint "
        f"still reports Contact={described.get('Contact')!r}"
    )

    account_after = acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"]
    assert account_after["Status"] == "REVOKED", (
        f"UpdateAcmeEndpoint mutated the unrelated revoked account's status to {account_after['Status']!r}"
    )

    control_arn = _create_active_endpoint(ctx, acm, contact="NOT_REQUIRED")
    acm.update_acme_endpoint(AcmeEndpointArn=control_arn, Contact="REQUIRED")
    control_described = acm.describe_acme_endpoint(AcmeEndpointArn=control_arn)["AcmeEndpoint"]
    assert control_described.get("Contact") == "REQUIRED", (
        f"positive control: UpdateAcmeEndpoint(Contact=REQUIRED) on an unrelated endpoint with "
        f"no revoked account did not take effect, got Contact={control_described.get('Contact')!r}"
    )


def _delete_if_present(fn):
    """Teardown delete: return once it succeeds or the resource is already gone, retry a
    ConflictException while a dependent resource is still being released, raise the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NoSuchEntity"):
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(
    acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _binding_client(ctx, iam, sts, role_arns):
    # CreateAcmeExternalAccountBinding needs iam:PassRole on each binding role; a role the check
    # creates holds only that grant and the create call, so the calling identity's own policies
    # stay untouched.
    identity = sts.get_caller_identity()
    name = ctx.unique_name("sim2real-acme-eab-binder-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{identity['Account']}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:userid": identity["UserId"]}},
            }
        ],
    }
    binder_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": list(role_arns),
            },
            {"Effect": "Allow", "Action": "acm:CreateAcmeExternalAccountBinding", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=name, PolicyName="acme-eab-binder", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="acme-eab-binder"))
    # A new role's trust policy propagates with a lag; retry only the documented denial.
    deadline = time.monotonic() + min(60.0, ctx.time_left() or 60.0)
    while True:
        try:
            creds = sts.assume_role(RoleArn=binder_arn, RoleSessionName="acme-eab-binder")["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    return ctx.client(
        "acm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _create_eab_with_retry(
    ctx, acm, endpoint_arn: str, role_arn: str, timeout_s: float = 180.0, interval_s: float = 2.0
) -> str:
    """IAM role creation and the binder role's PassRole policy are both eventually consistent:
    until they settle ACM answers AccessDeniedException (PassRole) or UnrecognizedClientException
    (fresh session), so only those two answers are retried to a deadline."""
    deadline = time.monotonic() + min(timeout_s, ctx.time_left() or timeout_s)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
            )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"create_acme_external_account_binding for role {role_arn} never succeeded within "
        f"{timeout_s}s of IAM role/policy propagation, last error: {last_exc}"
    )


def _wait_for_account_status(
    acm, endpoint_arn: str, account_url: str, target_statuses: set, timeout_s: float = 30.0, interval_s: float = 2.0
) -> dict:
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
