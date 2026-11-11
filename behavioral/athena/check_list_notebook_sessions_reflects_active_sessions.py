"""list-notebook-sessions-reflects-active-sessions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-notebook-sessions-reflects-active-sessions"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A session started on a notebook appears in ListNotebookSessions and stays listed after
    GetSessionStatus reports TERMINATED: the list is a lifetime roster, not a live-state filter."""
    athena = ctx.client("athena")
    setup = _setup_spark_workgroup(ctx)
    workgroup = setup["workgroup"]

    notebook_name = ctx.unique_name("sim2real-nb-lns-")
    notebook_id = athena.create_notebook(WorkGroup=workgroup, Name=notebook_name)["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(athena, notebook_id))

    before = athena.list_notebook_sessions(NotebookId=notebook_id)["NotebookSessionsList"]
    assert before == [], f"expected no sessions on a fresh notebook, got {before!r}"

    session_id = _start_session(
        ctx,
        workgroup,
        extra_engine_config={"AdditionalConfigs": {"NotebookId": notebook_id}},
        NotebookVersion="Athena notebook version 1",
    )

    active = athena.list_notebook_sessions(NotebookId=notebook_id)["NotebookSessionsList"]
    active_ids = {s["SessionId"] for s in active}
    assert session_id in active_ids, f"expected {session_id} in active sessions, got {active_ids!r}"

    athena.terminate_session(SessionId=session_id)
    terminated_status = _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"],
        lambda st: st["State"] == "TERMINATED",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert terminated_status["State"] == "TERMINATED", (
        f"expected GetSessionStatus to report TERMINATED, got {terminated_status!r}"
    )

    # ListNotebookSessions carries only SessionId/CreationTime (no state, no state filter)
    # and keeps terminated sessions.
    after = athena.list_notebook_sessions(NotebookId=notebook_id)["NotebookSessionsList"]
    after_ids = {s["SessionId"] for s in after}
    assert session_id in after_ids, (
        f"expected {session_id} to remain on the notebook's session roster after "
        f"termination, got {after_ids!r}"
    )


def _safe_delete_notebook(athena: Any, notebook_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        athena.delete_notebook(NotebookId=notebook_id)
    except ClientError as exc:
        if not _not_found(exc):
            raise


def _not_found(exc: ClientError) -> bool:
    """Athena reports a missing resource as ResourceNotFoundException or an InvalidRequestException saying so."""
    err = exc.response["Error"]
    msg = err.get("Message", "")
    return err.get("Code") == "ResourceNotFoundException" or (
        err.get("Code") == "InvalidRequestException" and ("not found" in msg or "does not exist" in msg)
    )


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
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
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
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        timeout_s=60.0,
    )

    def _cleanup_wg() -> None:
        try:
            athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
        except ClientError as exc:
            if not _not_found(exc):
                raise

    ctx.on_cleanup(_cleanup_wg)

    return {"workgroup": workgroup, "bucket": bucket_name, "role_arn": role_arn}


def _start_session(ctx, workgroup: str, extra_engine_config: dict[str, Any] | None = None, **kwargs) -> str:
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    engine_configuration = {
        "CoordinatorDpuSize": 1,
        "MaxConcurrentDpus": 3,
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
        # A notebook bound to a session that is still terminating cannot be deleted.
        _poll_until(
            lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
            lambda s: s in ("TERMINATED", "FAILED"),
            timeout_s=60.0,
            interval_s=2.0,
        )

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
