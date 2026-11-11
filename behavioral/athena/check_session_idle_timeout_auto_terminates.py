"""session-idle-timeout-auto-terminates."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-idle-timeout-auto-terminates"
GROUP = "visibility-timeout-ttl"
SERVICES = ["athena"]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/athena/latest/APIReference/API_StartSession.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A session left idle beyond its configured SessionIdleTimeoutInMinutes automatically
    transitions to TERMINATED (observable via GetSessionStatus), without an explicit
    TerminateSession call."""
    bucket = _create_bucket(ctx)
    role_arn = _create_spark_execution_role(ctx, bucket)
    wg_name = _create_spark_workgroup(ctx, bucket, role_arn)

    athena = ctx.client("athena")
    idle_timeout_minutes = 1
    session_id = _start_spark_session(ctx, wg_name, idle_timeout_minutes=idle_timeout_minutes)
    idle_since = time.monotonic()

    # Do nothing: leave the session idle and wait for the documented idle-timeout window
    # (SessionIdleTimeoutInMinutes=1) to elapse, then poll for the auto-termination.
    final_state = _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
        lambda s: s in ("TERMINATING", "TERMINATED", "FAILED", "DEGRADED"),
        timeout_s=600,
        interval_s=10,
    )
    if final_state == "TERMINATING":
        final_state = _poll_until(
            lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
            lambda s: s == "TERMINATED",
            timeout_s=300,
            interval_s=10,
        )
    elapsed_idle_s = time.monotonic() - idle_since
    assert final_state == "TERMINATED", f"expected idle session to auto-terminate, got {final_state}"
    # Two-sided: the session must not have been reaped for some unrelated reason faster than
    # its own configured idle window — otherwise any target that kills sessions on a fixed
    # short clock, independent of SessionIdleTimeoutInMinutes, would score green here.
    min_expected_s = idle_timeout_minutes * 60 - 15
    assert elapsed_idle_s >= min_expected_s, (
        f"session auto-terminated after {elapsed_idle_s:.0f}s idle, faster than its configured "
        f"{idle_timeout_minutes}-minute (>= {min_expected_s}s) idle timeout allows"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-spark-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "session-idle-timeout-auto-terminates"}]},
    )

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_spark_execution_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "session-idle-timeout-auto-terminates"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:DescribeLogStreams",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                ],
                "Resource": [
                    f"arn:aws:logs:{ctx.region}:{account_id}:log-group:/aws-athena:*",
                    f"arn:aws:logs:{ctx.region}:{account_id}:log-group:/aws-athena*:log-stream:*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": "logs:DescribeLogGroups",
                "Resource": f"arn:aws:logs:{ctx.region}:{account_id}:log-group:*",
            },
            {
                "Effect": "Allow",
                "Action": ["cloudwatch:PutMetricData"],
                "Resource": "*",
                "Condition": {"StringEquals": {"cloudwatch:namespace": "AmazonAthenaForApacheSpark"}},
            },
        ],
    }
    policy_name = "sim2real-athena-spark-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    # IAM eventual consistency before Athena can assume the new role is handled by
    # _start_spark_session's own bounded retry loop below, not by a fixed sleep here.
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_spark_workgroup(ctx, bucket_name: str, role_arn: str) -> str:
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-spark-wg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket_name}/spark-output/"},
            "ExecutionRole": role_arn,
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
        },
        Tags=[{"Key": "sim2real", "Value": "session-idle-timeout-auto-terminates"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))
    return wg_name


def _start_spark_session(ctx, wg_name: str, idle_timeout_minutes: int) -> str:
    athena = ctx.client("athena")
    engine_cfg = {"CoordinatorDpuSize": 1, "DefaultExecutorDpuSize": 1, "MaxConcurrentDpus": 2}

    session_id = None
    last_error = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            session_id = athena.start_session(
                WorkGroup=wg_name,
                EngineConfiguration=engine_cfg,
                SessionIdleTimeoutInMinutes=idle_timeout_minutes,
            )["SessionId"]
            break
        except ClientError as exc:
            last_error = exc
            time.sleep(2)
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (IAM role propagation?): {last_error}")

    ctx.on_cleanup(lambda: _safe_terminate(ctx, session_id))

    state = _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
        lambda s: s in ("IDLE", "FAILED", "DEGRADED"),
        timeout_s=600,
        interval_s=10,
    )
    if state != "IDLE":
        raise AssertionError(f"session did not reach IDLE, got {state}")
    return session_id


def _safe_terminate(ctx, session_id: str) -> None:
    athena = ctx.client("athena")
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
