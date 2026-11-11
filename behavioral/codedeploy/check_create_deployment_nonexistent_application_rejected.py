"""create-deployment-nonexistent-application-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-nonexistent-application-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment against an application name that was never created raises
    ApplicationDoesNotExistException, the call has no side effect (the application still
    does not exist), and a real application/deployment group/revision still deploys."""
    cd = ctx.client("codedeploy")

    missing_app = ctx.unique_name("sim2real-cd-missing-app-")
    expected_message = f"No application found for name: {missing_app}"
    code, message = _error(lambda: cd.create_deployment(applicationName=missing_app, deploymentGroupName="whatever"))
    assert code == "ApplicationDoesNotExistException", (
        f"CreateDeployment against a never-created application {missing_app!r} returned "
        f"{code!r}, expected ApplicationDoesNotExistException"
    )
    assert message == expected_message, f"CreateDeployment message {message!r}, expected {expected_message!r}"

    # effect absent: CreateDeployment did not implicitly create the application
    code2, message2 = _error(lambda: cd.get_application(applicationName=missing_app))
    assert code2 == "ApplicationDoesNotExistException", (
        f"GetApplication for {missing_app!r} returned {code2!r} after the rejected "
        f"CreateDeployment, expected ApplicationDoesNotExistException (no implicit creation)"
    )
    assert message2 == expected_message, f"GetApplication message {message2!r}, expected {expected_message!r}"

    # positive control: a real application + deployment group + revision deploys successfully
    app_name = _create_application(ctx)
    role_arn = _create_service_role(ctx)
    group_name = _create_deployment_group(ctx, app_name, role_arn)
    deployment_id = _create_deployment(ctx, app_name, group_name)
    assert deployment_id, "CreateDeployment against a real application/group returned no deploymentId"

    # terminal read: an independent GetDeployment, not the mutating call's own response
    info = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert info["applicationName"] == app_name, (
        f"GetDeployment({deployment_id!r}) reports applicationName {info['applicationName']!r}, "
        f"expected {app_name!r}"
    )
    assert info["deploymentGroupName"] == group_name, (
        f"GetDeployment({deployment_id!r}) reports deploymentGroupName "
        f"{info['deploymentGroupName']!r}, expected {group_name!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
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


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _create_deployment_group(ctx, app_name, role_arn, timeout_s=90.0):
    cd = ctx.client("codedeploy")
    group_name = ctx.unique_name("sim2real-cd-dg-")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
            )
            ctx.on_cleanup(
                lambda: cd.delete_deployment_group(
                    applicationName=app_name, deploymentGroupName=group_name
                )
            )
            return group_name
        except ClientError as exc:
            # freshly created IAM roles can take a few seconds to propagate
            if exc.response["Error"]["Code"] == "InvalidRoleException":
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _create_deployment(ctx, app_name, group_name):
    cd = ctx.client("codedeploy")
    bucket = f"aws-codedeploy-{ctx.region}"
    resp = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        revision={
            "revisionType": "S3",
            "s3Location": {
                "bucket": bucket,
                "key": "samples/latest/SampleApp_Linux.zip",
                "bundleType": "zip",
            },
        },
    )
    return resp["deploymentId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
