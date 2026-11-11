"""start-calculation-execution-on-terminated-session-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-calculation-execution-on-terminated-session-rejected"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCalculationExecution succeeds on a live session but is rejected with
    InvalidRequestException once the session is TERMINATED, and the rejected call creates no
    calculation."""
    athena = ctx.client("athena")
    setup = _setup_spark_workgroup(ctx)
    session_id = _start_session(ctx, setup["workgroup"])

    started = athena.start_calculation_execution(
        SessionId=session_id, CodeBlock="spark.sql('SELECT 1').show()"
    )
    calc_id = started["CalculationExecutionId"]
    _poll_until(
        lambda: athena.get_calculation_execution_status(CalculationExecutionId=calc_id)["Status"],
        lambda st: st["State"] in ("COMPLETED", "FAILED", "CANCELED"),
        timeout_s=240.0,
        interval_s=8.0,
    )
    before_count = len(athena.list_calculation_executions(SessionId=session_id)["Calculations"])
    assert before_count == 1, (
        f"positive-control calculation not visible via ListCalculationExecutions: "
        f"expected 1 entry, got {before_count}"
    )

    athena.terminate_session(SessionId=session_id)
    _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"],
        lambda st: st["State"] == "TERMINATED",
        timeout_s=180.0,
        interval_s=5.0,
    )

    err = _error(
        lambda: athena.start_calculation_execution(
            SessionId=session_id, CodeBlock="spark.sql('SELECT 2').show()"
        )
    )
    # The terminated session still exists, so Athena reports an invalid state, not not-found.
    expected = (
        "InvalidRequestException",
        "Session is in the TERMINATED state; needs to be IDLE to accept Calculations.",
    )
    assert err == expected, (
        f"StartCalculationExecution against a terminated session: expected "
        f"{expected}, got {err!r}"
    )

    after_count = len(athena.list_calculation_executions(SessionId=session_id)["Calculations"])
    assert after_count == before_count == 1, (
        f"rejected StartCalculationExecution changed the visible calculation count: "
        f"expected {before_count}, got {after_count}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


_SPARK_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
    "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
]


def _setup_spark_workgroup(ctx) -> dict[str, str]:
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "athena.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup_role() -> None:
        for policy_arn in _SPARK_POLICIES:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    for policy_arn in _SPARK_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    bucket_name = ctx.unique_name("sim2real-athena-spark-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup_bucket() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)

    workgroup = ctx.unique_name("sim2real-spark-wg-")
    athena.create_work_group(
        Name=workgroup,
        Configuration={
            "ExecutionRole": role_arn,
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket_name}/"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup_wg() -> None:
        try:
            athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err.get("Code") == "InvalidRequestException" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup_wg)

    return {"workgroup": workgroup, "bucket": bucket_name, "role_arn": role_arn}


def _start_session(ctx, workgroup: str, extra_engine_config: dict[str, Any] | None = None, **kwargs) -> str:
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    engine_configuration = {
        "CoordinatorDpuSize": 1,
        "MaxConcurrentDpus": 2,
        "DefaultExecutorDpuSize": 1,
    }
    if extra_engine_config:
        engine_configuration.update(extra_engine_config)

    # A just-created role may not be assumable yet (IAM propagation), so retry on that failure.
    deadline = time.monotonic() + 60.0
    last_err = None
    session_id = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=workgroup, EngineConfiguration=engine_configuration, **kwargs
            )
            session_id = resp["SessionId"]
            break
        except ClientError as err:
            msg = str(err).lower()
            if any(k in msg for k in ("dpu", "capacity", "quota", "limit")):
                raise AssertionError(f"Spark session capacity unavailable: {err}") from err
            if "assume" not in msg and "not authorized" not in msg and "access denied" not in msg:
                raise
            last_err = err
            time.sleep(5.0)
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (role propagation?): {last_err}")

    def _cleanup_session() -> None:
        try:
            st = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if st not in ("TERMINATED", "TERMINATING", "FAILED"):
            try:
                athena.terminate_session(SessionId=session_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_session)

    try:
        _poll_until(
            lambda: athena.get_session_status(SessionId=session_id)["Status"],
            lambda st: st["State"] in ("IDLE", "FAILED", "DEGRADED"),
            timeout_s=420.0,
            interval_s=10.0,
        )
    except TimeoutError:
        raise AssertionError("session did not leave CREATING within timeout")

    final_state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    if final_state != "IDLE":
        raise AssertionError(f"session reached {final_state} instead of IDLE (environment issue)")

    return session_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
