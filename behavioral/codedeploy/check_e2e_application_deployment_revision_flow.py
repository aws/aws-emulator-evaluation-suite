"""e2e-application-deployment-revision-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-application-deployment-revision-flow"
GROUP = "e2e"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create an application and deployment group, register a revision, create a
    deployment against it, observe the deployment reach a terminal state referencing that
    revision, then tear down and confirm the application is gone."""
    cd = ctx.client("codedeploy")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    key = "releases/app.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-codedeploy-e2e-fixture")
    revision = {"revisionType": "S3", "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip"}}

    role_arn = _create_service_role(ctx)

    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}]

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(applicationName=app_name, computePlatform="Server", tags=resource_tags)
    app_deleted = False
    ctx.on_cleanup(lambda: None if app_deleted else cd.delete_application(applicationName=app_name))

    dg_name = ctx.unique_name("sim2real-cddg-")
    # A tag filter guaranteed to match zero real EC2 instances -- exercises the
    # documented NO_INSTANCES failure path deterministically without provisioning EC2.
    _create_deployment_group_with_role_retry(
        ctx,
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        ec2TagFilters=[
            {"Key": "sim2real-unmatched-tag", "Value": ctx.unique_name("no-such-value-"), "Type": "KEY_AND_VALUE"}
        ],
        tags=resource_tags,
    )

    cd.register_application_revision(applicationName=app_name, revision=revision)

    deployment_id = cd.create_deployment(
        applicationName=app_name, deploymentGroupName=dg_name, revision=revision
    )["deploymentId"]

    deployment_info = _poll_until(
        lambda: cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"],
        lambda info: info["status"] in ("Succeeded", "Failed", "Stopped"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    status = deployment_info["status"]
    assert status == "Failed", f"expected a zero-instance deployment group to fail, got status={status!r}"
    error_code = deployment_info["errorInformation"]["code"]
    assert error_code == "NO_INSTANCES", f"expected errorInformation.code=NO_INSTANCES, got {error_code!r}"
    got_app = deployment_info["applicationName"]
    assert got_app == app_name, f"expected deployment applicationName={app_name!r}, got {got_app!r}"
    got_dg = deployment_info["deploymentGroupName"]
    assert got_dg == dg_name, f"expected deployment deploymentGroupName={dg_name!r}, got {got_dg!r}"
    got_bucket = deployment_info["revision"]["s3Location"]["bucket"]
    assert got_bucket == bucket, f"expected deployment revision bucket={bucket!r}, got {got_bucket!r}"
    got_key = deployment_info["revision"]["s3Location"]["key"]
    assert got_key == key, f"expected deployment revision key={key!r}, got {got_key!r}"

    revisions = cd.list_application_revisions(applicationName=app_name)["revisions"]
    assert any(
        r.get("s3Location", {}).get("bucket") == bucket and r.get("s3Location", {}).get("key") == key
        for r in revisions
    ), f"registered revision {bucket}/{key} not found via list_application_revisions: {revisions!r}"

    cd.delete_application(applicationName=app_name)
    app_deleted = True

    code, message = _error(lambda: cd.get_application(applicationName=app_name))
    assert code == "ApplicationDoesNotExistException", (
        f"expected get_application on a deleted application to raise ApplicationDoesNotExistException, got {code!r}"
    )
    assert message == f"No application found for name: {app_name}", message


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdbkt-").lower()
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" -- the
    # region-free call is how you create a bucket there. Not a target-region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_role_retry(ctx, cd, **kwargs):
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return cd.create_deployment_group(**kwargs)
        except cd.exceptions.InvalidRoleException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never became true, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _error(fn):
    """Call fn(); return (code, message) of its error. An unexpected SUCCESS raises, so a
    target that still answers for a deleted application never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
