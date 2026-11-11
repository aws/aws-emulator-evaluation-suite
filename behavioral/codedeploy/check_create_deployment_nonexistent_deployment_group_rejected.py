"""create-deployment-nonexistent-deployment-group-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-nonexistent-deployment-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment against a deployment group that was never created must be
    rejected outright, not silently create an orphaned deployment."""
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cd-app-")
    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}]
    cd.create_application(applicationName=app_name, computePlatform="Lambda", tags=resource_tags)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    revision = _lambda_appspec_revision("placeholder-function-name")
    bogus_group = ctx.unique_name("sim2real-cd-nogroup-")

    code, message = _error(
        lambda: cd.create_deployment(
            applicationName=app_name,
            deploymentGroupName=bogus_group,
            deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
            revision=revision,
        )
    )
    assert code == "DeploymentGroupDoesNotExistException", (
        f"expected DeploymentGroupDoesNotExistException for a never-created "
        f"deployment group, got {code!r}"
    )
    expected_message = f"No Deployment Group found for name: {bogus_group}"
    assert message == expected_message, f"CreateDeployment message {message!r}, expected {expected_message!r}"

    # the rejection must not have created a deployment group as a side effect
    listed = cd.list_deployment_groups(applicationName=app_name)["deploymentGroups"]
    assert bogus_group not in listed, (
        f"rejected CreateDeployment must not leave an orphaned deployment group; "
        f"found {bogus_group!r} in {listed!r}"
    )

    # positive control: a deployment group that actually exists accepts CreateDeployment
    role_arn = _create_lambda_codedeploy_role(ctx)
    group_name = ctx.unique_name("sim2real-cd-group-")
    _create_deployment_group_with_retry(ctx, cd, app_name, group_name, role_arn, resource_tags)

    resp = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce",
        revision=revision,
    )
    assert resp["deploymentId"], f"expected a deploymentId, got {resp!r}"
    info = cd.get_deployment(deploymentId=resp["deploymentId"])["deploymentInfo"]
    assert info["deploymentGroupName"] == group_name, (
        f"expected the deployment's own deployment group to be {group_name!r}, "
        f"got {info['deploymentGroupName']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _lambda_appspec_revision(function_name: str) -> dict:
    appspec = json.dumps(
        {
            "version": "0.0",
            "resources": [
                {
                    "myLambdaFunction": {
                        "type": "AWS::Lambda::Function",
                        "properties": {
                            "name": function_name,
                            "alias": "live",
                            "currentversion": "1",
                            "targetversion": "2",
                        },
                    }
                }
            ],
        }
    )
    return {"revisionType": "AppSpecContent", "appSpecContent": {"content": appspec}}


def _create_lambda_codedeploy_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust = {
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_deployment_group_with_retry(
    ctx, cd, app_name: str, group_name: str, role_arn: str, tags: list, timeout_s: float = 90.0
) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
                deploymentStyle={
                    "deploymentType": "BLUE_GREEN",
                    "deploymentOption": "WITH_TRAFFIC_CONTROL",
                },
                tags=tags,
            )
            ctx.on_cleanup(
                lambda: cd.delete_deployment_group(
                    applicationName=app_name, deploymentGroupName=group_name
                )
            )
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "InvalidRoleException":
                raise
            time.sleep(3)
    raise AssertionError(f"deployment group never became creatable, last error {last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
