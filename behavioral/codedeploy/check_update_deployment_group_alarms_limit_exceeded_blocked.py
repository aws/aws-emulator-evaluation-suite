"""update-deployment-group-alarms-limit-exceeded-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-deployment-group-alarms-limit-exceeded-blocked"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeploymentGroup rejects an enabled-but-empty alarm list and duplicate alarm names with
    InvalidAlarmConfigException, leaving the stored alarms untouched, while a well-formed update
    and an 11-alarm over-quota list are both accepted and persisted in full."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)
    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    group = ctx.unique_name("sim2real-cd-dg-")
    seed_alarm = ctx.unique_name("sim2real-alarm-")
    _create_deployment_group(
        ctx, cd, app, group, role_arn,
        alarmConfiguration={"enabled": True, "alarms": [{"name": seed_alarm}]},
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )

    # Negative: enabled=True with an empty alarm list is explicitly documented as
    # invalid -- must be rejected, not silently applied.
    error = _client_error(lambda: cd.update_deployment_group(
        applicationName=app,
        currentDeploymentGroupName=group,
        alarmConfiguration={"enabled": True, "alarms": []},
    ))
    assert error == (
        "InvalidAlarmConfigException",
        "Deployment Groups need to have at least one alarms attached if they are monitored.",
    ), error

    # Negative #2: duplicate alarm names in the same request -- also documented as
    # invalid.
    error2 = _client_error(lambda: cd.update_deployment_group(
        applicationName=app,
        currentDeploymentGroupName=group,
        alarmConfiguration={"enabled": True, "alarms": [{"name": seed_alarm}, {"name": seed_alarm}]},
    ))
    assert error2 == (
        "InvalidAlarmConfigException",
        f"Name {seed_alarm} of Alarm 2 already exists.",
    ), error2

    unchanged = cd.get_deployment_group(applicationName=app, deploymentGroupName=group)["deploymentGroupInfo"]
    unchanged_names = {a["name"] for a in unchanged["alarmConfiguration"]["alarms"]}
    assert unchanged_names == {seed_alarm}, unchanged_names

    # Positive control: a well-formed alarm configuration update is applied and persisted.
    other_alarm = ctx.unique_name("sim2real-alarm-ok-")
    cd.update_deployment_group(
        applicationName=app,
        currentDeploymentGroupName=group,
        alarmConfiguration={"enabled": True, "alarms": [{"name": other_alarm}]},
    )
    persisted = cd.get_deployment_group(applicationName=app, deploymentGroupName=group)["deploymentGroupInfo"]
    persisted_names = {a["name"] for a in persisted["alarmConfiguration"]["alarms"]}
    assert persisted_names == {other_alarm}, persisted_names

    # The documented "maximum 10 alarms per deployment group" quota is enforced on
    # CreateDeployment's overrideAlarmConfiguration but empirically is NOT enforced synchronously
    # here: UpdateDeploymentGroup accepts and fully persists an over-quota alarm list rather than
    # rejecting it. Assert that divergence explicitly so a target that starts enforcing it -- or one
    # that silently truncates instead of storing every entry -- is caught either way.
    over_quota_alarms = [{"name": ctx.unique_name(f"sim2real-alarm-many-{i}-")} for i in range(11)]
    cd.update_deployment_group(
        applicationName=app,
        currentDeploymentGroupName=group,
        alarmConfiguration={"enabled": True, "alarms": over_quota_alarms},
    )
    over_quota = cd.get_deployment_group(applicationName=app, deploymentGroupName=group)["deploymentGroupInfo"]
    over_quota_names = {a["name"] for a in over_quota["alarmConfiguration"]["alarms"]}
    assert over_quota_names == {a["name"] for a in over_quota_alarms}, over_quota_names


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
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


def _create_deployment_group(ctx, cd, application_name, deployment_group_name, service_role_arn, **kwargs):
    deadline = time.monotonic() + 30
    while True:
        try:
            resp = cd.create_deployment_group(
                applicationName=application_name,
                deploymentGroupName=deployment_group_name,
                serviceRoleArn=service_role_arn,
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cd.delete_deployment_group(
        applicationName=application_name, deploymentGroupName=deployment_group_name
    ))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
