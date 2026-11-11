"""webapp-customization-logo-binary-round-trip."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webapp-customization-logo-binary-round-trip"
GROUP = "representation"
SERVICES = ["transfer"]

# A minimal valid 1x1 transparent PNG (68 bytes decoded). UpdateWebAppCustomization
# validates LogoFile as an actual image, so it must be a real (if tiny) PNG.
_MINIMAL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A binary LogoFile blob written via UpdateWebAppCustomization is returned byte-for-byte
    identical by DescribeWebAppCustomization."""
    transfer = ctx.client("transfer")
    instance_arn = _identity_center_instance_arn(ctx)
    role_arn = _create_transfer_role(ctx)

    web_app_id = _create_web_app_with_retry(transfer, instance_arn, role_arn, ctx.unique_name("sim2real-webapp-"))
    ctx.on_cleanup(lambda: transfer.delete_web_app(WebAppId=web_app_id))
    ctx.on_cleanup(lambda: _delete_customization_if_present(transfer, web_app_id))

    logo_bytes = base64.b64decode(_MINIMAL_PNG_B64)
    transfer.update_web_app_customization(WebAppId=web_app_id, LogoFile=logo_bytes)

    described = transfer.describe_web_app_customization(WebAppId=web_app_id)["WebAppCustomization"]
    returned = described["LogoFile"]
    returned_bytes = returned.read() if hasattr(returned, "read") else bytes(returned)
    assert returned_bytes == logo_bytes, (
        f"logo bytes mangled in round trip: sent {len(logo_bytes)} bytes, got {len(returned_bytes)} bytes"
    )


def _identity_center_instances(ctx):
    """The account's IAM Identity Center instances, creating one if the account has none.

    `sso-admin:CreateInstance` provisions a
    STANDALONE (non-Organizations) instance, so the prerequisite is satisfiable in-check and an
    absent instance is a property of the account, not of the service. Exactly one instance is
    allowed per account and deleting it would disrupt any other check relying on it, so one created
    here is deliberately never torn down.
    """
    import time

    from botocore.exceptions import ClientError

    sso_idc = ctx.client("sso-admin")
    try:
        instances = sso_idc.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']})"
        ) from exc
    if not instances:
        sso_idc.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.time() + 120
    while time.time() < deadline:
        found = sso_idc.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        if any(i.get("Status") == "ACTIVE" and "IdentityStoreId" in i for i in found):
            return found
        time.sleep(3)
    raise AssertionError(
        "IAM Identity Center instance did not become ACTIVE with an IdentityStoreId within 120s"
    )

def _create_web_app_with_retry(transfer, instance_arn: str, role_arn: str, name_tag: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> str:
    """CreateWebApp validates the Role's trust policy immediately, but that trust
    policy can take a few seconds to become visible outside IAM; retry against the
    observable rejection rather than sleeping a fixed, unaccountable delay."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return transfer.create_web_app(
                IdentityProviderDetails={"IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}},
                Tags=[{"Key": "Name", "Value": name_tag}],
            )["WebAppId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"create_web_app did not succeed within {timeout_s}s (IAM role propagation?): {last_exc}")


def _identity_center_instance_arn(ctx) -> str:
    instances = _identity_center_instances(ctx)
    return instances[0]["InstanceArn"]


def _delete_customization_if_present(transfer, web_app_id: str) -> None:
    try:
        transfer.delete_web_app_customization(WebAppId=web_app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-webapp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
