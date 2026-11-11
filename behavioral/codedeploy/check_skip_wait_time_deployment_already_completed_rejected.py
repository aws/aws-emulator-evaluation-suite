"""skip-wait-time-deployment-already-completed-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "skip-wait-time-deployment-already-completed-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SkipWaitTimeForInstanceTermination on a Failed deployment fails with DeploymentAlreadyCompletedException
    and leaves it Failed, while StopDeployment on an in-flight deployment of the same group drives it to
    Stopped.
    """
    role_arn = _create_codedeploy_service_role(ctx)
    bundle = _upload_minimal_bundle(ctx)
    app_name, group_name = _create_app_and_empty_deployment_group(ctx, role_arn)

    deployment_id = _create_deployment(ctx, app_name, group_name, bundle)
    status = _wait_terminal(ctx, deployment_id)
    assert status == "Failed"

    cd = ctx.client("codedeploy")
    refusal = _error(
        lambda: cd.skip_wait_time_for_instance_termination(deploymentId=deployment_id)
    )
    expected = ("DeploymentAlreadyCompletedException",
                f"The deployment {deployment_id} has already completed, current state FAILED.")
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # effect absent: the deployment's status did not change as a result of the rejected call
    status_after = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
    assert status_after == "Failed"

    # positive control: a fresh deployment on the same group is genuinely controllable while
    # still in flight - StopDeployment is accepted and drives it to Stopped, a *different*
    # terminal state than the Failed one above, proving the completion gate is state-specific
    # rather than the group/pipeline rejecting or failing everything outright
    deployment_id_2 = _create_deployment(ctx, app_name, group_name, bundle)
    stop_resp = _stop_deployment_with_retry(cd, deployment_id_2)
    assert stop_resp["status"] in ("Pending", "Succeeded"), f"unexpected stop_resp {stop_resp}"
    status_2 = _wait_terminal(ctx, deployment_id_2)
    assert status_2 == "Stopped", f"expected Stopped after StopDeployment, got {status_2}"


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _upload_minimal_bundle(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-bundle-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", "version: 0.0\nos: linux\nfiles: []\n")
    key = "bundle.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return {"bucket": bucket, "key": key, "bundleType": "zip"}


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_app_and_empty_deployment_group(ctx, role_arn):
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    group_name = ctx.unique_name("sim2real-cd-dg-")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
                deploymentStyle={
                    "deploymentType": "BLUE_GREEN",
                    "deploymentOption": "WITH_TRAFFIC_CONTROL",
                },
                blueGreenDeploymentConfiguration={
                    "terminateBlueInstancesOnDeploymentSuccess": {"action": "KEEP_ALIVE"},
                    "deploymentReadyOption": {
                        "actionOnTimeout": "CONTINUE_DEPLOYMENT",
                        "waitTimeInMinutes": 0,
                    },
                    "greenFleetProvisioningOption": {"action": "DISCOVER_EXISTING"},
                },
                loadBalancerInfo={
                    "elbInfoList": [{"name": ctx.unique_name("sim2real-cd-elb-")}]
                },
                ec2TagFilters=[
                    {
                        "Key": "sim2real-behavioral-nonexistent-tag",
                        "Value": "none",
                        "Type": "KEY_AND_VALUE",
                    }
                ],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=group_name)
    )
    return app_name, group_name


def _create_deployment(ctx, app_name, group_name, bundle, **kwargs):
    cd = ctx.client("codedeploy")
    return cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        revision={"revisionType": "S3", "s3Location": bundle},
        **kwargs,
    )["deploymentId"]


def _stop_deployment_with_retry(cd, deployment_id, timeout_s=60.0):
    """StopDeployment can transiently 400 with InvalidDeploymentStatusException if called in
    the brief window before the deployment engine has registered the deployment as
    in-progress; retry until it is genuinely stoppable."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cd.stop_deployment(deploymentId=deployment_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidDeploymentStatusException":
                raise
            last_exc = exc
            time.sleep(2.0)
    raise AssertionError(f"deployment {deployment_id} never became stoppable: {last_exc}")


def _wait_terminal(ctx, deployment_id, timeout_s=240.0):
    cd = ctx.client("codedeploy")
    terminal = {"Succeeded", "Failed", "Stopped"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
        if status in terminal:
            return status
        time.sleep(5.0)
    raise AssertionError(f"deployment {deployment_id} never reached a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
