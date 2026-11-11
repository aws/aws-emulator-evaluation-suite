"""get-acme-external-account-binding-credentials-server-generated-hmac."""
from __future__ import annotations

import base64
import binascii
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "get-acme-external-account-binding-credentials-server-generated-hmac"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """GetAcmeExternalAccountBindingCredentials returns service-generated credentials: two bindings
    get distinct KeyIds and MacKeys of at least 16 decoded bytes, neither equal to the
    caller-supplied idempotency token."""
    acm = ctx.client("acm")
    endpoint_arn = _create_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)
    role_arn = _create_eab_role(ctx)
    _wait_role_usable(ctx, endpoint_arn, role_arn)

    seed_a = ctx.unique_name("sim2real-acm-eab-seed-a-")
    seed_b = ctx.unique_name("sim2real-acm-eab-seed-b-")

    eab_a_arn = acm.create_acme_external_account_binding(
        AcmeEndpointArn=endpoint_arn, RoleArn=role_arn, IdempotencyToken=seed_a
    )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_a_arn))

    eab_b_arn = acm.create_acme_external_account_binding(
        AcmeEndpointArn=endpoint_arn, RoleArn=role_arn, IdempotencyToken=seed_b
    )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_b_arn))

    creds_a = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_a_arn
    )
    creds_b = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_b_arn
    )

    assert creds_a["KeyId"] != creds_b["KeyId"], "two distinct bindings got the same KeyId"
    assert creds_a["MacKey"] != creds_b["MacKey"], "two distinct bindings got the same MacKey"

    for seed, creds in ((seed_a, creds_a), (seed_b, creds_b)):
        assert creds["KeyId"] != seed, "KeyId must not equal the caller-supplied idempotency seed"
        assert creds["MacKey"] != seed, "MacKey must not equal the caller-supplied idempotency seed"
        raw = _decode_b64(creds["MacKey"])
        assert len(raw) >= 16, f"MacKey decodes to only {len(raw)} bytes -- insufficient entropy"


def _decode_b64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except binascii.Error:
        return base64.b64decode(value + padding)


def _create_endpoint(ctx: Any) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_EAB_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    from botocore.exceptions import ClientError

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
