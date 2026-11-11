"""stop-deployment-already-completed-blocked."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-deployment-already-completed-blocked"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopDeployment on a Failed deployment fails with DeploymentAlreadyCompletedException and leaves it Failed,
    while StopDeployment on an in-flight deployment of the same group is accepted and drives it to Stopped.
    """
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)
    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(applicationName=app, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    revision = _upload_s3_revision(ctx)

    # Group A: tag filter that can never match any real instance -> the deployment
    # fails fast with "no instances found", reaching a terminal state quickly.
    dead_group = ctx.unique_name("sim2real-cd-dg-dead-")
    _create_deployment_group(
        ctx, cd, app, dead_group, role_arn,
        onPremisesInstanceTagFilters=[
            {"Key": ctx.unique_name("sim2real-nomatch-"), "Value": "none", "Type": "KEY_AND_VALUE"}
        ],
    )

    # Group B: tag filter matches a registered-but-agentless on-premises instance ->
    # the deployment stays active (waiting for a check-in that will never happen),
    # giving us a reliable window to stop it while it is still non-terminal.
    live_group = ctx.unique_name("sim2real-cd-dg-live-")
    instance_name = ctx.unique_name("sim2real-cd-onprem-")
    account_id = _account_id(ctx)
    iam_user_arn = f"arn:aws:iam::{account_id}:user/{instance_name}"
    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=iam_user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))
    tag_key = ctx.unique_name("sim2real-tag-")
    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": tag_key, "Value": "match"}], instanceNames=[instance_name]
    )
    _create_deployment_group(
        ctx, cd, app, live_group, role_arn,
        onPremisesInstanceTagFilters=[{"Key": tag_key, "Value": "match", "Type": "KEY_AND_VALUE"}],
    )

    # Positive control: stop a still-active deployment -> accepted.
    live_deployment_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=live_group, revision=revision["location"]
    )["deploymentId"]
    stop_resp = cd.stop_deployment(deploymentId=live_deployment_id)
    assert stop_resp["status"] in ("Succeeded", "Pending"), stop_resp["status"]
    final_live = _wait_deployment_status(cd, live_deployment_id, {"Succeeded", "Failed", "Stopped"})
    assert final_live["status"] == "Stopped", final_live["status"]

    # Negative: stop a deployment that already reached a terminal state -> rejected.
    dead_deployment_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dead_group, revision=revision["location"]
    )["deploymentId"]
    terminal = _wait_deployment_status(cd, dead_deployment_id, {"Succeeded", "Failed", "Stopped"})
    assert terminal["status"] == "Failed", terminal["status"]
    assert terminal.get("errorInformation") == {
        "code": "NO_INSTANCES",
        "message": "The deployment failed because no instances were found for your deployment "
        "group. Check your deployment group settings to make sure the tags for your Amazon EC2 "
        "instances or Auto Scaling groups correctly identify the instances you want to deploy "
        "to, and then try again.",
    }, terminal.get("errorInformation")

    error = _client_error(lambda: cd.stop_deployment(deploymentId=dead_deployment_id))
    assert error == (
        "DeploymentAlreadyCompletedException",
        f"The deployment {dead_deployment_id} is already in state FAILED",
    ), error

    # The rejected stop must not have changed the terminal deployment's status.
    unchanged = cd.get_deployment(deploymentId=dead_deployment_id)["deploymentInfo"]
    assert unchanged["status"] == "Failed", unchanged["status"]


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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


def _minimal_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", "version: 0.0\nos: linux\nfiles: []\n")
    return buf.getvalue()


def _upload_s3_revision(ctx, key="revision.zip"):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return {
        "bucket": bucket,
        "key": key,
        "location": {"revisionType": "S3", "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip"}},
    }


def _wait_deployment_status(cd, deployment_id, target_statuses, timeout_s=150.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"deployment {deployment_id} did not reach {target_statuses} within {timeout_s}s "
        f"(last status={last['status'] if last else None})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
