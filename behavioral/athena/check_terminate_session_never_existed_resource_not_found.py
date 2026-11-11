"""terminate-session-never-existed-resource-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-session-never-existed-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateSession on a session id that was never created raises InvalidRequestException, not the
    documented ResourceNotFoundException, while terminating a real fresh session succeeds."""
    athena = ctx.client("athena")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    role_arn = _create_spark_execution_role(ctx, iam)
    bucket = _create_output_bucket(ctx, s3)
    workgroup = ctx.unique_name("sim2real-athena-sparkwg-")
    athena.create_work_group(
        Name=workgroup,
        Configuration={
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"},
        },
        Tags=[{"Key": "sim2real", "Value": "terminate-session-never-existed"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True))

    session_id = _start_session_with_retry(athena, workgroup, role_arn)
    if session_id is None:
        raise AssertionError(
            "unable to start a Spark session in this account/region within the retry budget"
        )
    ctx.on_cleanup(lambda: _best_effort_terminate(athena, session_id))

    # Positive control: TerminateSession succeeds on a real, freshly-issued session id.
    positive = athena.terminate_session(SessionId=session_id)
    assert positive["State"] in ("TERMINATING", "TERMINATED"), (
        f"positive control: expected TERMINATING/TERMINATED terminating a real session, "
        f"got {positive['State']}"
    )

    never_existed_session_id = str(uuid.uuid4())
    code, message = _error_code(lambda: athena.terminate_session(SessionId=never_existed_session_id))
    assert code == "InvalidRequestException", (
        f"TerminateSession on a never-existed SessionId: expected InvalidRequestException, got {code}"
    )
    assert message == "Not authorized to make this request.", (
        f"expected the exact InvalidRequestException message AWS returns, got {message!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("TerminateSession on a never-existed SessionId unexpectedly succeeded")


def _best_effort_terminate(athena, session_id):
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_spark_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-athena-sparkrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "terminate-session-never-existed"}],
    )["Role"]

    def _cleanup_role() -> None:
        for arn in (
            "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
            "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
        ):
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    for arn in (
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    return role["Arn"]


def _start_session_with_retry(athena, workgroup, role_arn, timeout_s=90, interval_s=10):
    """StartSession can fail while the role's trust policy has not yet propagated to
    Athena's STS AssumeRole path; retry within a bounded budget rather than sleeping
    blindly before the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=workgroup,
                ExecutionRole=role_arn,
                EngineConfiguration={
                    "CoordinatorDpuSize": 1,
                    # MaxConcurrentDpus has a service-enforced minimum of 2; a value of
                    # 1 fails client-side parameter validation.
                    "MaxConcurrentDpus": 2,
                    "DefaultExecutorDpuSize": 1,
                },
            )
            return resp["SessionId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    if last_exc is not None:
        return None
    return None


def _create_output_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-athena-out-").replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 is CreateBucket's own special case: passing a LocationConstraint
        # for it is itself rejected, not a check-level region pin.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
