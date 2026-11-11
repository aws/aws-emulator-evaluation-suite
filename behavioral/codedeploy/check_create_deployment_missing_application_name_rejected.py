"""create-deployment-missing-application-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-missing-application-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment with an empty-string applicationName raises
    ApplicationNameRequiredException, while a call carrying a real applicationName (plus
    group/revision) still succeeds."""
    ctx.client("codedeploy")

    # botocore's local parameter validation rejects an empty string for applicationName
    # (min length 1) before the request ever leaves the client, so a second client with
    # parameter_validation disabled (same resolved credentials/region as the normal client) is
    # used to reach the service and observe its own, documented, server-side
    # ApplicationNameRequiredException.
    cd_novalidate = ctx.client("codedeploy", config=Config(parameter_validation=False))
    code, message = _error(
        lambda: cd_novalidate.create_deployment(
            applicationName="", deploymentGroupName="whatever-group"
        )
    )
    assert code == "ApplicationNameRequiredException", f"got {code!r}"
    assert message == "Application name is missing", f"got {message!r}"

    # positive control: same shape of call, but with a real applicationName, succeeds
    app_name = _create_application(ctx)
    role_arn = _create_service_role(ctx)
    group_name = _create_deployment_group(ctx, app_name, role_arn)
    deployment_id = _create_deployment(ctx, app_name, group_name)
    assert deployment_id, "CreateDeployment with a real applicationName returned no deploymentId"

    # terminal read: independent of the mutating CreateDeployment call, at the destination
    info = ctx.client("codedeploy").get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert info["applicationName"] == app_name, f"got {info['applicationName']!r}"
    assert info["deploymentGroupName"] == group_name, f"got {info['deploymentGroupName']!r}"


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


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
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
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
                tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(
                lambda: cd.delete_deployment_group(
                    applicationName=app_name, deploymentGroupName=group_name
                )
            )
            return group_name
        except ClientError as exc:
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
