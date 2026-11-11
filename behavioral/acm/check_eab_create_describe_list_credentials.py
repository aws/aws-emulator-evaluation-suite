"""eab-create-describe-list-credentials."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eab-create-describe-list-credentials"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new EAB on an active ACME endpoint is immediately returned by Describe and List with its
    RoleArn and endpoint, and its credentials (KeyId, MacKey) are retrievable."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx)
    role_arn = _create_acme_role(ctx)

    eab_arn, created = _create_eab(ctx, endpoint_arn, role_arn)
    assert eab_arn.startswith(f"{endpoint_arn}/acme-external-account-binding/"), (
        f"unexpected EAB arn shape: {eab_arn}"
    )
    assert created["RoleArn"] == role_arn, f"expected RoleArn {role_arn}, got {created['RoleArn']}"
    assert created["AcmeEndpointArn"] == endpoint_arn, (
        f"expected AcmeEndpointArn {endpoint_arn}, got {created['AcmeEndpointArn']}"
    )
    assert created.get("RevokedAt") is None, "freshly created EAB must not be revoked"

    described = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert described["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"describe returned a different ARN: expected {eab_arn}, got "
        f"{described['AcmeExternalAccountBindingArn']}"
    )
    assert described["RoleArn"] == role_arn, f"expected RoleArn {role_arn}, got {described['RoleArn']}"
    assert described["AcmeEndpointArn"] == endpoint_arn, (
        f"expected AcmeEndpointArn {endpoint_arn}, got {described['AcmeEndpointArn']}"
    )

    bindings = []
    token = None
    while True:
        kwargs = {"AcmeEndpointArn": endpoint_arn}
        if token:
            kwargs["NextToken"] = token
        page = acm.list_acme_external_account_bindings(**kwargs)
        bindings.extend(page.get("ExternalAccountBindings", []))
        token = page.get("NextToken")
        if not token:
            break
    arns = [b["AcmeExternalAccountBindingArn"] for b in bindings]
    assert eab_arn in arns, f"created EAB {eab_arn} not found in list: {arns}"

    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    assert isinstance(creds["KeyId"], str) and len(creds["KeyId"]) > 0, f"KeyId not a non-empty string: {creds.get('KeyId')!r}"
    assert isinstance(creds["MacKey"], str) and len(creds["MacKey"]) > 0, (
        f"MacKey not a non-empty string: {creds.get('MacKey')!r}"
    )


def _create_active_endpoint(ctx) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(ctx, arn))
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        ep = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if ep["Status"] == "ACTIVE":
            return arn
        if ep["Status"] == "FAILED":
            raise AssertionError(f"ACME endpoint entered FAILED: {ep.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError("ACME endpoint did not reach ACTIVE status within timeout")


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
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
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
                Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
