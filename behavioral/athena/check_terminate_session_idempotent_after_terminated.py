"""terminate-session-idempotent-after-terminated."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "terminate-session-idempotent-after-terminated"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second TerminateSession on an already TERMINATED session succeeds as a no-op, as
    documented, and GetSessionStatus still reports TERMINATED afterward."""
    athena = ctx.client("athena")
    iam = ctx.client("iam")

    role_arn = _create_spark_execution_role(ctx, iam)
    workgroup = _create_spark_workgroup(ctx, athena, role_arn)

    session_id = _start_session_with_retry(athena, workgroup, role_arn)
    ctx.on_cleanup(lambda: _best_effort_terminate(athena, session_id))

    ready_state = _poll_session_state(
        athena, session_id, {"IDLE", "TERMINATED", "FAILED", "DEGRADED"}, timeout_s=420.0
    )
    if ready_state != "IDLE":
        raise AssertionError(
            f"Spark session never reached IDLE within the poll window (last state={ready_state!r})"
        )

    first_response = athena.terminate_session(SessionId=session_id)
    assert first_response["State"] in ("TERMINATING", "TERMINATED"), first_response

    terminated_state = _poll_session_state(athena, session_id, {"TERMINATED"}, timeout_s=180.0)
    assert terminated_state == "TERMINATED", f"session never reached TERMINATED: {terminated_state!r}"

    second_response = athena.terminate_session(SessionId=session_id)
    assert second_response["State"] == "TERMINATED", (
        f"expected idempotent TERMINATED response, got {second_response!r}"
    )

    status_after = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    assert status_after == "TERMINATED", f"repeat TerminateSession mutated session state: {status_after!r}"


def _create_spark_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
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
    try:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]
    except ClientError as e:
        raise AssertionError(f"cannot create IAM role for Spark session in this account: {e}") from e
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    return role["Arn"]


def _delete_role(iam, role_name):
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for p in attached:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_spark_workgroup(ctx, athena, role_arn):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-spark-").lower().replace("_", "-")
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" -- that region is
    # the only one that must omit the field entirely.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _cleanup_bucket(s3, bucket))

    name = ctx.unique_name("sim2real-athena-spark-wg-")
    athena.create_work_group(
        Name=name,
        Configuration={
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    # Athena provisions a CloudWatch log group for the Spark workgroup that
    # DeleteWorkGroup does not remove.
    ctx.on_cleanup(lambda: _delete_spark_log_group(ctx, name))
    return name


def _delete_spark_log_group(ctx, workgroup_name):
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws-athena/{workgroup_name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cleanup_bucket(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _start_session_with_retry(athena, workgroup, role_arn, timeout_s=180.0, interval_s=10.0):
    """Retry StartSession, which can reject a just-created role until IAM propagation completes."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return athena.start_session(
                WorkGroup=workgroup,
                ExecutionRole=role_arn,
                EngineConfiguration={
                    "CoordinatorDpuSize": 1,
                    "MaxConcurrentDpus": 3,
                    "DefaultExecutorDpuSize": 1,
                },
            )["SessionId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"unable to start a Spark session in this account within {timeout_s}s (IAM role propagation?): {last_exc}"
    ) from last_exc


def _poll_session_state(athena, session_id, target_states, timeout_s):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(2)
    return state


def _best_effort_terminate(athena, session_id):
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
