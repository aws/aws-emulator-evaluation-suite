"""deployment-group-invalid-role-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deployment-group-invalid-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentGroup with a non-assumable serviceRoleArn raises InvalidRoleException and creates
    no group, while a real assumable role creates one."""
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-no-such-role-')}"
    bad_dg_name = ctx.unique_name("sim2real-cddg-bad-")

    code, message = _error(
        lambda: cd.create_deployment_group(
            applicationName=app_name, deploymentGroupName=bad_dg_name, serviceRoleArn=bogus_role_arn
        )
    )
    assert code == "InvalidRoleException", f"expected InvalidRoleException, got {code!r}"
    assert message == (
        f"AWS CodeDeploy does not have the permissions required to assume the role {bogus_role_arn}."
    ), message

    absent_code, absent_message = _error(
        lambda: cd.get_deployment_group(applicationName=app_name, deploymentGroupName=bad_dg_name)
    )
    assert absent_code == "DeploymentGroupDoesNotExistException", (
        f"expected DeploymentGroupDoesNotExistException, got {absent_code!r}"
    )
    assert absent_message == f"No Deployment Group found for name: {bad_dg_name}", absent_message

    # Positive control: a real, assumable role succeeds for the same application.
    good_role_arn = _create_service_role(ctx)
    good_dg_name = ctx.unique_name("sim2real-cddg-good-")
    _create_deployment_group_with_role_retry(
        ctx,
        cd,
        applicationName=app_name,
        deploymentGroupName=good_dg_name,
        serviceRoleArn=good_role_arn,
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=good_dg_name)
    )
    resp = cd.get_deployment_group(applicationName=app_name, deploymentGroupName=good_dg_name)
    actual_name = resp["deploymentGroupInfo"]["deploymentGroupName"]
    assert actual_name == good_dg_name, f"expected deployment group {good_dg_name!r}, got {actual_name!r}"


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_role_retry(ctx, cd, **kwargs):
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return cd.create_deployment_group(**kwargs)
        except cd.exceptions.InvalidRoleException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _error(fn):
    """Call fn(); return (code, message) of its error. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
