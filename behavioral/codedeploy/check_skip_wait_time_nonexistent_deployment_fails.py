"""skip-wait-time-nonexistent-deployment-fails."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "skip-wait-time-nonexistent-deployment-fails"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SkipWaitTimeForInstanceTermination on a nonexistent deploymentId is rejected,
    while a real deployment's id remains resolvable through GetDeployment (positive
    control proving the existence check is precise, not a blanket rejection)."""
    codedeploy = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    codedeploy.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    role_arn = _create_codedeploy_service_role(ctx)

    dg_name = ctx.unique_name("sim2real-cddg-")
    _create_deployment_group_with_retry(
        codedeploy,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        ec2TagFilters=[
            {"Key": "sim2real-no-match", "Value": ctx.unique_name("nope-"), "Type": "KEY_AND_VALUE"}
        ],
    )
    ctx.on_cleanup(lambda: codedeploy.delete_deployment_group(applicationName=app_name, deploymentGroupName=dg_name))

    revision = _upload_revision_bundle(ctx)
    real_deployment_id = codedeploy.create_deployment(
        applicationName=app_name,
        deploymentGroupName=dg_name,
        revision=revision,
    )["deploymentId"]

    # Fake, well-formed but never-created deployment id.
    fake_id = "d-" + uuid.uuid4().hex[:9].upper()

    refusal = _error(lambda: codedeploy.skip_wait_time_for_instance_termination(deploymentId=fake_id))
    expected = ("DeploymentDoesNotExistException", f"The deployment {fake_id} could not be found")
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Positive control: the real deployment id is genuinely tracked by the service.
    real = codedeploy.get_deployment(deploymentId=real_deployment_id)
    assert real["deploymentInfo"]["deploymentId"] == real_deployment_id, (
        f"expected deploymentId {real_deployment_id!r}, got {real['deploymentInfo'].get('deploymentId')!r}"
    )
    assert real["deploymentInfo"]["applicationName"] == app_name, (
        f"expected applicationName {app_name!r}, got {real['deploymentInfo'].get('applicationName')!r}"
    )

    # Positive control on the operation under test itself: without this, a target that
    # unconditionally returns DeploymentDoesNotExistException for every deploymentId (real or
    # fake) would still pass the assertion above. Calling the same operation on the real,
    # in-place deployment id must be rejected for a DIFFERENT, precise reason -- proving the
    # existence check is specific and not a blanket rejection.
    real_refusal = _error(
        lambda: codedeploy.skip_wait_time_for_instance_termination(deploymentId=real_deployment_id)
    )
    expected = ("UnsupportedActionForDeploymentTypeException",
                f"Operation is not supported for the deployment {real_deployment_id} of type IN_PLACE.")
    assert real_refusal == expected, (
        f"expected {expected!r} for an in-place deployment, got {real_refusal!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_codedeploy_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
    import io
    import zipfile

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
