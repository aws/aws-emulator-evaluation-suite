"""deployment-create-observe-terminal-status."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-create-observe-terminal-status"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployment to a group matching zero EC2 instances ends Failed with error code NO_INSTANCES
    (CodeDeploy needs an InService instance), visible in GetDeployment and ListDeployments."""
    role_arn = _create_service_role(ctx)
    revision = _create_revision_bucket(ctx)
    app_name = _create_application(ctx)
    group_name = _create_empty_deployment_group(ctx, app_name, role_arn)
    deployment_id = _create_deployment(ctx, app_name, group_name, revision)

    status = _poll_deployment_status(ctx, deployment_id, {"Failed", "Succeeded", "Stopped"})
    assert status == "Failed", f"expected Failed for a zero-instance deployment group, got {status}"

    cd = ctx.client("codedeploy")
    detail = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert detail["status"] == "Failed", f"expected Failed, got {detail['status']}"
    assert detail["deploymentId"] == deployment_id, (
        f"expected deploymentId {deployment_id}, got {detail['deploymentId']}"
    )
    assert detail["applicationName"] == app_name, (
        f"expected applicationName {app_name}, got {detail['applicationName']}"
    )
    assert detail["deploymentGroupName"] == group_name, (
        f"expected deploymentGroupName {group_name}, got {detail['deploymentGroupName']}"
    )
    # Failed alone could mean any cause (bad role, bad revision); the code pins the reason.
    error_info = detail.get("errorInformation") or {}
    assert error_info.get("code") == "NO_INSTANCES", (
        f"expected errorInformation.code NO_INSTANCES, got {error_info}"
    )

    listed_ids = cd.list_deployments(
        applicationName=app_name, deploymentGroupName=group_name
    )["deployments"]
    assert deployment_id in listed_ids, (
        f"expected {deployment_id} in list_deployments result, got {listed_ids}"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_revision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-")
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; this is the S3
    # API's own quirk, not a region pin on the bucket itself.
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
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
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
    cd.create_application(applicationName=app_name, computePlatform="Server")
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
