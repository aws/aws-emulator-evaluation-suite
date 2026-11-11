"""deployment-group-update-reflected-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-update-reflected-lifecycle"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeploymentGroup changes to ec2TagFilters and alarmConfiguration are persisted
    and visible on a subsequent GetDeploymentGroup."""
    codedeploy = ctx.client("codedeploy")
    role_arn = _create_codedeploy_service_role(ctx)

    app_name = ctx.unique_name("sim2real-cd-app-")
    codedeploy.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    group_name = ctx.unique_name("sim2real-cd-dg-")
    initial_filter = {"Key": "sim2real-cd-tag", "Value": "v1", "Type": "KEY_AND_VALUE"}
    _create_deployment_group_with_role_retry(
        ctx,
        codedeploy,
        app_name,
        group_name,
        role_arn,
        ec2TagFilters=[initial_filter],
        alarmConfiguration={"enabled": False, "ignorePollAlarmFailure": False, "alarms": []},
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: codedeploy.delete_deployment_group(
            applicationName=app_name, deploymentGroupName=group_name
        )
    )

    before = codedeploy.get_deployment_group(
        applicationName=app_name, deploymentGroupName=group_name
    )["deploymentGroupInfo"]
    assert before["ec2TagFilters"] == [initial_filter], before["ec2TagFilters"]
    assert before["alarmConfiguration"]["enabled"] is False, before["alarmConfiguration"]

    updated_filter = {"Key": "sim2real-cd-tag", "Value": "v2", "Type": "KEY_AND_VALUE"}
    alarm_name = ctx.unique_name("sim2real-cd-alarm-")
    codedeploy.update_deployment_group(
        applicationName=app_name,
        currentDeploymentGroupName=group_name,
        ec2TagFilters=[updated_filter],
        alarmConfiguration={
            "enabled": True,
            "ignorePollAlarmFailure": False,
            "alarms": [{"name": alarm_name}],
        },
    )

    after = codedeploy.get_deployment_group(
        applicationName=app_name, deploymentGroupName=group_name
    )["deploymentGroupInfo"]
    assert after["ec2TagFilters"] == [updated_filter], after["ec2TagFilters"]
    assert after["alarmConfiguration"]["enabled"] is True, after["alarmConfiguration"]
    assert after["alarmConfiguration"]["alarms"] == [{"name": alarm_name}], after[
        "alarmConfiguration"
    ]["alarms"]


def _create_codedeploy_service_role(ctx):
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_role_retry(
    ctx, codedeploy, application_name, deployment_group_name, role_arn, **kwargs
):
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return codedeploy.create_deployment_group(
                applicationName=application_name,
                deploymentGroupName=deployment_group_name,
                serviceRoleArn=role_arn,
                **kwargs,
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"deployment group never became creatable, last error: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
