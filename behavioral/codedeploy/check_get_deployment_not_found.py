"""get-deployment-not-found."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployment-not-found"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeployment on a well-formed never-created id raises DeploymentDoesNotExistException naming the
    id, while a real deployment id resolves."""
    cd = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    role_arn = _create_codedeploy_service_role(ctx)

    dg_name = ctx.unique_name("sim2real-cddg-")
    _create_deployment_group_with_retry(
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        ec2TagFilters=[
            {"Key": "sim2real-no-match", "Value": ctx.unique_name("nope-"), "Type": "KEY_AND_VALUE"}
        ],
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    )

    revision = _upload_revision_bundle(ctx)
    real_deployment_id = cd.create_deployment(
        applicationName=app_name,
        deploymentGroupName=dg_name,
        revision=revision,
    )["deploymentId"]

    # Positive control: the real deployment id is genuinely tracked by the service.
    real = cd.get_deployment(deploymentId=real_deployment_id)
    assert real["deploymentInfo"]["deploymentId"] == real_deployment_id, real
    assert real["deploymentInfo"]["applicationName"] == app_name, real

    # Fake, well-formed but never-created deployment id.
    fake_id = "d-" + uuid.uuid4().hex[:9].upper()
    code, message = _error(lambda: cd.get_deployment(deploymentId=fake_id))
    assert code == "DeploymentDoesNotExistException", f"expected DeploymentDoesNotExistException, got {code}"
    assert message == f"The deployment {fake_id} could not be found", message


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected DeploymentDoesNotExistException, but the call SUCCEEDED and returned {result!r}"
    )


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_retry(codedeploy, *, timeout_s=45.0, **kwargs):
    """IAM role propagation is eventually consistent; retry InvalidRoleException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return codedeploy.create_deployment_group(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _upload_revision_bundle(ctx) -> dict:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdrev-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        s3.delete_object(Bucket=bucket, Key="revision.zip")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    appspec = "version: 0.0\nos: linux\nfiles:\n  - source: /\n    destination: /tmp/sim2real\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", appspec)
    put_resp = s3.put_object(Bucket=bucket, Key="revision.zip", Body=buf.getvalue())
    etag = put_resp["ETag"].strip('"')
    return {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": "revision.zip", "bundleType": "zip", "eTag": etag},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
