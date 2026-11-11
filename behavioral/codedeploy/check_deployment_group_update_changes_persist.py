"""deployment-group-update-changes-persist."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-update-changes-persist"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeploymentGroup's new deploymentConfigName and ec2TagFilters read back on GetDeploymentGroup
    and differ from the values read after create."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)
    app_name = _create_application(ctx)

    custom_config_name = ctx.unique_name("sim2real-cd-cfg-")
    cd.create_deployment_config(
        deploymentConfigName=custom_config_name,
        minimumHealthyHosts={"type": "FLEET_PERCENT", "value": 50},
        computePlatform="Server",
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=custom_config_name))

    group_name = ctx.unique_name("sim2real-cd-dg-")
    initial_tag_key = ctx.unique_name("sim2real-cd-tag-initial-")
    updated_tag_key = ctx.unique_name("sim2real-cd-tag-updated-")

    _create_deployment_group_with_role_retry(
        ctx,
        app_name,
        group_name,
        role_arn,
        deploymentConfigName="CodeDeployDefault.AllAtOnce",
        ec2TagFilters=[{"Key": initial_tag_key, "Value": "v1", "Type": "KEY_AND_VALUE"}],
    )

    before = cd.get_deployment_group(
        applicationName=app_name, deploymentGroupName=group_name
    )["deploymentGroupInfo"]
    assert before["deploymentConfigName"] == "CodeDeployDefault.AllAtOnce", (
        f"expected CodeDeployDefault.AllAtOnce, got {before['deploymentConfigName']!r}"
    )
    assert before["ec2TagFilters"] == [
        {"Key": initial_tag_key, "Value": "v1", "Type": "KEY_AND_VALUE"}
    ], f"expected initial tag filter, got {before['ec2TagFilters']!r}"

    cd.update_deployment_group(
        applicationName=app_name,
        currentDeploymentGroupName=group_name,
        deploymentConfigName=custom_config_name,
        ec2TagFilters=[{"Key": updated_tag_key, "Value": "v2", "Type": "KEY_AND_VALUE"}],
    )

    after = cd.get_deployment_group(
        applicationName=app_name, deploymentGroupName=group_name
    )["deploymentGroupInfo"]
    assert after["deploymentConfigName"] == custom_config_name, (
        f"expected {custom_config_name!r}, got {after['deploymentConfigName']!r}"
    )
    assert after["ec2TagFilters"] == [
        {"Key": updated_tag_key, "Value": "v2", "Type": "KEY_AND_VALUE"}
    ], f"expected updated tag filter, got {after['ec2TagFilters']!r}"
    assert after["deploymentConfigName"] != before["deploymentConfigName"], (
        "deploymentConfigName did not change across update "
        f"(stuck at {before['deploymentConfigName']!r})"
    )
    assert after["ec2TagFilters"] != before["ec2TagFilters"], (
        f"ec2TagFilters did not change across update (stuck at {before['ec2TagFilters']!r})"
    )


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codedeploy.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_application(ctx):
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))
    return app_name


def _create_deployment_group_with_role_retry(ctx, app_name, group_name, role_arn, **kwargs):
    cd = ctx.client("codedeploy")
    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
                tags=[
                    {"Key": "sim2real:managed", "Value": "true"},
                    {"Key": "sim2real", "Value": CHECK},
                ],
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException":
                raise
            last_error = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"service role never became assumable: {last_error}")
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(
            applicationName=app_name, deploymentGroupName=group_name
        )
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
