"""put-lifecycle-event-hook-status-deployment-not-exist-rejected."""
from __future__ import annotations

import json
import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-lifecycle-event-hook-status-deployment-not-exist-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLifecycleEventHookExecutionStatus on an unknown deployment ID fails with
    DeploymentDoesNotExistException, while on a real deployment with a fabricated hook execution ID it fails
    with InvalidLifecycleEventHookExecutionIdException; both with their exact messages.
    """
    cd = ctx.client("codedeploy")

    fake_deployment_id = _fake_deployment_id()
    code, message = _error(
        lambda: cd.put_lifecycle_event_hook_execution_status(
            deploymentId=fake_deployment_id,
            lifecycleEventHookExecutionId="sim2real-hook-1",
            status="Succeeded",
        )
    )
    assert code == "DeploymentDoesNotExistException", (
        f"expected DeploymentDoesNotExistException for a deployment id that was never "
        f"created, got {code!r}"
    )
    assert message == f"The deployment {fake_deployment_id} could not be found", f"got {message!r}"

    # contrast: the same call against a REAL deployment reaches a different, specific
    # validation branch -- the deployment exists, but this fabricated hook execution id was
    # never issued for it.
    app_name = _create_application(ctx)
    role_arn = _create_service_role(ctx)
    group_name = _create_deployment_group(ctx, app_name, role_arn)
    deployment_id = _create_deployment(ctx, app_name, group_name)

    code2, message2 = _error(
        lambda: cd.put_lifecycle_event_hook_execution_status(
            deploymentId=deployment_id,
            lifecycleEventHookExecutionId="sim2real-hook-1",
            status="Succeeded",
        )
    )
    if code2 != "InvalidLifecycleEventHookExecutionIdException":
        raise AssertionError(
            f"expected InvalidLifecycleEventHookExecutionIdException for a fabricated hook "
            f"execution id against a real deployment, got {code2!r}"
        )
    assert message2 == "The lifecycleEventHookExecutionId is invalid", f"got {message2!r}"
    assert code2 != code, (
        f"expected the missing-deployment error and the invalid-hook-execution-id error to "
        f"differ, both were {code!r}"
    )

    # terminal read: an independent GetDeployment call (not the mutating
    # PutLifecycleEventHookExecutionStatus call) proves the real deployment is unaffected by
    # the two rejected status calls -- it is still there, under the same id.
    detail = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert detail["deploymentId"] == deployment_id, (
        f"expected the real deployment to remain readable under {deployment_id!r} after the "
        f"rejected hook-status calls, got deploymentId={detail.get('deploymentId')!r}"
    )


def _fake_deployment_id():
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=9))
    return f"d-{suffix}"


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
        tags=[{"Key": "sim2real", "Value": "true"}],
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
                tags=[{"Key": "sim2real", "Value": "true"}],
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
