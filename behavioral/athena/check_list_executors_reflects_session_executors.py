"""list-executors-reflects-session-executors."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-executors-reflects-session-executors"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExecutors returns the executor set allocated to an active session, reflecting
    live DPU allocation state, including a coordinator that reaches REGISTERED."""
    athena = ctx.client("athena")
    setup = _setup_spark_workgroup(ctx)
    session_id = _start_session(ctx, setup["workgroup"])

    executors = _poll_until(
        lambda: athena.list_executors(SessionId=session_id)["ExecutorsSummary"],
        lambda execs: len(execs) >= 1
        and any(e["ExecutorState"] == "REGISTERED" for e in execs),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert len(executors) >= 1, f"expected >=1 executor for active session, got {executors!r}"
    coordinators = [e for e in executors if e.get("ExecutorType") == "COORDINATOR"]
    assert len(coordinators) == 1, f"expected exactly 1 COORDINATOR, got {coordinators!r}"
    assert coordinators[0]["ExecutorState"] == "REGISTERED", (
        f"expected coordinator REGISTERED, got {coordinators[0]['ExecutorState']!r}"
    )

    athena.terminate_session(SessionId=session_id)
    _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"],
        lambda st: st["State"] == "TERMINATED",
        timeout_s=180.0,
        interval_s=5.0,
    )
    terminated_executors = athena.list_executors(SessionId=session_id)["ExecutorsSummary"]
    terminal_states = {"TERMINATING", "TERMINATED"}
    assert all(e["ExecutorState"] in terminal_states for e in terminated_executors), (
        f"expected all executors in {terminal_states} after termination, "
        f"got {[e['ExecutorState'] for e in terminated_executors]!r}"
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


def _retry_role_propagation(ctx, what: str, call: Callable[[], Any], timeout_s: float) -> Any:
    """Retry call() while Athena cannot yet use the just-created execution role (IAM propagation)."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))
    while True:
        try:
            return call()
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if not any(k in msg for k in ("misconfigured service role", "assume", "not authorized", "access denied")):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} never succeeded (role propagation?): {exc}") from exc
        time.sleep(2)


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
        Tags=[{"Key": "sim2real", "Value": "list-executors-reflects-session-executors"}],
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
        # us-east-1 rejects an explicit LocationConstraint on CreateBucket.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

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
    _retry_role_propagation(
        ctx,
        "CreateWorkGroup",
        lambda: athena.create_work_group(
            Name=workgroup,
            Configuration={
                "ExecutionRole": role_arn,
                "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
                "ResultConfiguration": {"OutputLocation": f"s3://{bucket_name}/"},
            },
            Tags=[{"Key": "sim2real", "Value": "list-executors-reflects-session-executors"}],
        ),
        timeout_s=60.0,
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

    session_id = _retry_role_propagation(
        ctx,
        "StartSession",
        lambda: athena.start_session(
            WorkGroup=workgroup, EngineConfiguration=engine_configuration, **kwargs
        )["SessionId"],
        timeout_s=60.0,
    )

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
