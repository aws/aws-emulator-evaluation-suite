"""continue-deployment-already-completed-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "continue-deployment-already-completed-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopDeployment on an in-progress deployment succeeds and drives it to Stopped;
    ContinueDeployment on that in-place deployment then raises
    UnsupportedActionForDeploymentTypeException (blue/green only), leaving the status as is."""
    role_arn = _create_service_role(ctx)
    revision = _create_revision_bucket(ctx)
    app_name = _create_application(ctx)
    group_name = _create_empty_deployment_group(ctx, app_name, role_arn)
    deployment_id = _create_deployment(ctx, app_name, group_name, revision)

    cd = ctx.client("codedeploy")

    # Positive control: stopping a deployment that has not yet completed succeeds.
    stop_resp = cd.stop_deployment(deploymentId=deployment_id)
    assert stop_resp["status"] in ("Pending", "Succeeded"), (
        f"expected StopDeployment to be accepted with status Pending/Succeeded, "
        f"got {stop_resp['status']!r}"
    )

    status = _poll_deployment_status(ctx, deployment_id, {"Stopped", "Failed", "Succeeded"})
    assert status == "Stopped", f"expected Stopped after StopDeployment, got {status}"

    code, message = _error(lambda: cd.continue_deployment(deploymentId=deployment_id))
    assert code == "UnsupportedActionForDeploymentTypeException", f"unexpected error code: {code!r}"
    expected = f"Operation is not supported for the deployment {deployment_id} of type IN_PLACE."
    assert message == expected, f"unexpected message: {message!r}, expected {expected!r}"

    # Effect absent: the rejected ContinueDeployment call did not move the deployment.
    unchanged = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
    assert unchanged == "Stopped", (
        f"expected status to remain Stopped after the rejected ContinueDeployment, "
        f"got {unchanged!r}"
    )


def _error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_revision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]},
    )
    key = "sim2real-app.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "appspec.yml",
            "version: 0.0\nos: linux\nfiles:\n  - source: /\n    destination: /tmp/sim2real\n",
        )
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return {"bucket": bucket, "key": key}


def _create_application(ctx):
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))
    return app_name


def _create_empty_deployment_group(ctx, app_name, role_arn):
    cd = ctx.client("codedeploy")
    group_name = ctx.unique_name("sim2real-cd-dg-")
    tag_key = ctx.unique_name("sim2real-cd-nomatch-")
    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            cd.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn=role_arn,
                ec2TagFilters=[{"Key": tag_key, "Value": "nomatch", "Type": "KEY_AND_VALUE"}],
                tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
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
    return group_name


def _create_deployment(ctx, app_name, group_name, revision):
    cd = ctx.client("codedeploy")
    resp = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=group_name,
        revision={
            "revisionType": "S3",
            "s3Location": {
                "bucket": revision["bucket"],
                "key": revision["key"],
                "bundleType": "zip",
            },
        },
    )
    return resp["deploymentId"]


def _poll_deployment_status(ctx, deployment_id, target_statuses, timeout_s=240.0, interval_s=5.0):
    cd = ctx.client("codedeploy")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"deployment {deployment_id} did not reach {target_statuses} within {timeout_s}s (last={status})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
