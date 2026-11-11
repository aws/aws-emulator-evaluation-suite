"""deployment-creation-timestamp-precision-preserved."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-creation-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The createTime timestamp returned for a deployment is stable and full precision:
    repeated GetDeployment calls and BatchGetDeployments return the exact same
    timezone-aware value, with no truncation or drift between calls or API surfaces."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)
    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    group = ctx.unique_name("sim2real-cd-dg-")
    _create_deployment_group(
        ctx, cd, app, group, role_arn,
        onPremisesInstanceTagFilters=[
            {"Key": ctx.unique_name("sim2real-nomatch-"), "Value": "none", "Type": "KEY_AND_VALUE"}
        ],
    )
    revision = _upload_s3_revision(ctx)
    deployment_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=group, revision=revision["location"]
    )["deploymentId"]

    first = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["createTime"]
    assert first.tzinfo is not None, "createTime is not timezone-aware"

    # Deliberate fixed wall-clock wait, not a poll: there is nothing to wait *for* here — the
    # point is that real time elapses, so a createTime that is silently recomputed (rather than
    # stored) or truncated to whole seconds has a real chance to show it on the second read.
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:
        time.sleep(0.1)
    second = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["createTime"]
    assert second == first, f"createTime drifted across GetDeployment calls: {first!r} != {second!r}"

    batch = cd.batch_get_deployments(deploymentIds=[deployment_id])["deploymentsInfo"][0]["createTime"]
    assert batch == first, f"createTime differs between GetDeployment and BatchGetDeployments: {first!r} != {batch!r}"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
