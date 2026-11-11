"""put-lifecycle-event-hook-invalid-deployment-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-lifecycle-event-hook-invalid-deployment-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLifecycleEventHookExecutionStatus rejects a malformed deployment id with
    InvalidDeploymentIdException and a well-formed missing id with DeploymentDoesNotExistException,
    while a real deployment stays readable."""
    role_arn = _create_service_role(ctx)
    revision = _create_revision_bucket(ctx)
    app_name = _create_application(ctx)
    group_name = _create_empty_deployment_group(ctx, app_name, role_arn)
    deployment_id = _create_deployment(ctx, app_name, group_name, revision)

    cd = ctx.client("codedeploy")

    malformed_id = "not a valid deployment id !!"
    error = _client_error(
        lambda: cd.put_lifecycle_event_hook_execution_status(
            deploymentId=malformed_id,
            lifecycleEventHookExecutionId="hook-1",
            status="Succeeded",
        )
    )
    assert error == (
        "InvalidDeploymentIdException",
        f"Specified DeploymentId is not in the valid format: {malformed_id}",
    ), (
        f"a syntactically malformed deployment id was rejected with {error!r}, "
        f'expected "InvalidDeploymentIdException"'
    )

    well_formed_missing_id = "d-ABCDEFGHI"
    error2 = _client_error(
        lambda: cd.put_lifecycle_event_hook_execution_status(
            deploymentId=well_formed_missing_id,
            lifecycleEventHookExecutionId="hook-1",
            status="Succeeded",
        )
    )
    assert error2 == (
        "DeploymentDoesNotExistException",
        f"The deployment {well_formed_missing_id} could not be found",
    ), (
        f"a well-formed but nonexistent deployment id was rejected with {error2!r}, "
        f'expected "DeploymentDoesNotExistException"'
    )

    detail = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
    assert detail["deploymentId"] == deployment_id, (
        f"the real deployment became unreadable after the negative calls: expected "
        f"deploymentId {deployment_id!r}, got {detail.get('deploymentId')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
