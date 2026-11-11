"""webapp-customization-update-reflected-immediately."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webapp-customization-update-reflected-immediately"
GROUP = "data-plane"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Immediately after UpdateWebAppCustomization returns, the very next
    DescribeWebAppCustomization call (no retry/poll) already serves the new title -- no
    stale-cache lag."""
    transfer = ctx.client("transfer")
    instance_arn = _identity_center_instance_arn(ctx)
    role_arn = _create_transfer_role(ctx)

    web_app_id = _retry_role_propagation(
        lambda: transfer.create_web_app(
            IdentityProviderDetails={"IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}},
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-webapp-")}],
        )
    )["WebAppId"]
    ctx.on_cleanup(lambda: transfer.delete_web_app(WebAppId=web_app_id))
    ctx.on_cleanup(lambda: _delete_customization_if_present(transfer, web_app_id))

    title = ctx.unique_name("Sim2Real Branding ")
    transfer.update_web_app_customization(WebAppId=web_app_id, Title=title)

    # No sleep, no retry loop: the very first read after the write must already be correct.
    described = transfer.describe_web_app_customization(WebAppId=web_app_id)["WebAppCustomization"]
    assert described["Title"] == title, f"stale read immediately after update: {described['Title']!r} != {title!r}"

    # A second update overwrites the first, and is again visible with no lag.
    title2 = title + "-v2"
    transfer.update_web_app_customization(WebAppId=web_app_id, Title=title2)
    described2 = transfer.describe_web_app_customization(WebAppId=web_app_id)["WebAppCustomization"]
    assert described2["Title"] == title2, f"stale read after second update: {described2['Title']!r} != {title2!r}"


def _identity_center_instance_arn(ctx) -> str:
    """Create-or-adopt: an account may already carry a standalone Identity Center instance
    (an account-global singleton, at most one per account), or CreateInstance can mint one."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]
    try:
        instance_arn = sso.create_instance(Name=ctx.unique_name("sim2real-identity-center-"))[
            "InstanceArn"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise
        instances = sso.list_instances().get("Instances", [])
        if not instances:
            raise AssertionError(
                f"CreateInstance reported a conflict ({exc}) but ListInstances still shows none"
            ) from exc
        return instances[0]["InstanceArn"]
    # Registered before the web app's teardown, so LIFO cleanup removes the instance last.
    ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))
    return instance_arn


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


def _retry_role_propagation(fn, attempts: int = 6, delay_s: float = 3.0):
    """Retry a call that depends on a just-created IAM role, tolerating IAM's eventual consistency."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
