"""session-lifecycle-start-get-status-endpoint-terminate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-lifecycle-start-get-status-endpoint-terminate"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Spark session reaches IDLE and is listed while live; GetSessionEndpoint refuses an IAM-role
    caller; TerminateSession drops it from ListSessions but it stays in ListNotebookSessions."""
    athena = ctx.client("athena")
    role_arn = _iam_role_for_spark(ctx)
    workgroup = _spark_workgroup(ctx, role_arn)
    notebook_id = athena.create_notebook(
        WorkGroup=workgroup, Name=ctx.unique_name("sim2real-nb-")
    )["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(ctx, notebook_id))

    session_id = _start_spark_session(ctx, workgroup, role_arn, notebook_id=notebook_id)

    session = athena.get_session(SessionId=session_id)
    assert session["WorkGroup"] == workgroup
    assert session["Status"]["State"] == "IDLE"

    status = athena.get_session_status(SessionId=session_id)["Status"]
    assert status["State"] == "IDLE"

    sessions = {s["SessionId"]: s for s in athena.list_sessions(WorkGroup=workgroup)["Sessions"]}
    assert session_id in sessions
    assert sessions[session_id]["Status"]["State"] == "IDLE"

    notebook_sessions = {
        s["SessionId"] for s in athena.list_notebook_sessions(NotebookId=notebook_id)["NotebookSessionsList"]
    }
    assert session_id in notebook_sessions

    # Athena refuses GetSessionEndpoint for an IAM-role caller with InvalidRequestException, even
    # while a calculation is RUNNING; the RUNNING calculation proves the session is healthy.
    calc_id = athena.start_calculation_execution(
        SessionId=session_id, CodeBlock="import time as _t\n_t.sleep(45)"
    )["CalculationExecutionId"]
    _poll_calc_state(ctx, calc_id, {"RUNNING"}, timeout_s=120)
    _assert_endpoint_consistently_unauthorized(ctx, session_id)
    _poll_calc_state(ctx, calc_id, {"COMPLETED", "FAILED", "CANCELED"}, timeout_s=240)

    athena.terminate_session(SessionId=session_id)
    state = _poll_session_state(ctx, session_id, {"TERMINATED", "FAILED"}, timeout_s=180)
    assert state == "TERMINATED", f"session never reached TERMINATED, ended at {state!r}"
    assert athena.get_session_status(SessionId=session_id)["Status"]["State"] == "TERMINATED"

    remaining = {s["SessionId"] for s in athena.list_sessions(WorkGroup=workgroup)["Sessions"]}
    assert session_id not in remaining, f"{session_id} still in ListSessions after termination"

    # Unlike ListSessions, ListNotebookSessions keeps terminated sessions listed (its summary has no
    # status field), despite its API description saying it lists active sessions.
    remaining_notebook_sessions = {
        s["SessionId"]
        for s in athena.list_notebook_sessions(NotebookId=notebook_id)["NotebookSessionsList"]
    }
    assert session_id in remaining_notebook_sessions, (
        f"{session_id} unexpectedly dropped from ListNotebookSessions after termination"
    )


def _iam_role_for_spark(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "athena.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policies = [
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    ]
    for arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _spark_workgroup(ctx, role_arn):
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-spark-wg-")
    # Real AWS requires ResultConfiguration on CreateWorkGroup even for a Spark
    # (interactive) workgroup.
    bucket = _s3_output_bucket(ctx)
    athena.create_work_group(
        Name=name,
        Configuration={
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-spark-results/"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    return name


def _s3_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_calc_state(ctx, calc_id, target_states, timeout_s, interval_s=4.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_calculation_execution_status(CalculationExecutionId=calc_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"calculation {calc_id} never reached {target_states}, timed out at {state!r}"
    )


def _assert_endpoint_consistently_unauthorized(ctx, session_id, attempts=5, interval_s=5.0):
    athena = ctx.client("athena")
    for _ in range(attempts):
        try:
            athena.get_session_endpoint(SessionId=session_id)
        except ClientError as exc:
            err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            expected = ("InvalidRequestException", "Not authorized to make this request.")
            assert err == expected, f"expected {expected}, got {err}"
        else:
            raise AssertionError("GetSessionEndpoint unexpectedly succeeded for a RUNNING calculation")
        time.sleep(interval_s)


def _poll_session_state(ctx, session_id, target_states, timeout_s, interval_s=6.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    return state


def _start_spark_session(ctx, workgroup, role_arn, notebook_id=None, timeout_s=480):
    athena = ctx.client("athena")
    # A notebook-bound session (NotebookVersion set below) enforces a higher
    # MaxConcurrentDpus floor than a plain session; real AWS rejects 2 here with
    # InvalidRequestException ("...less than minimum allowed length 3").
    engine_config = {"CoordinatorDpuSize": 1, "MaxConcurrentDpus": 3, "DefaultExecutorDpuSize": 1}
    kwargs = {}
    if notebook_id:
        engine_config["AdditionalConfigs"] = {"NotebookId": notebook_id}
        kwargs["NotebookVersion"] = "Athena notebook version 1"
    session_id = None
    last_exc = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            session_id = athena.start_session(
                WorkGroup=workgroup, ExecutionRole=role_arn,
                EngineConfiguration=engine_config, **kwargs,
            )["SessionId"]
            break
        except ClientError as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("dpu", "capacity", "quota", "limit")):
                raise AssertionError(f"Spark session capacity unavailable: {exc}") from exc
            # The IAM role just created can take a few seconds to propagate before
            # Athena is able to assume it; retry rather than sleeping unconditionally.
            last_exc = exc
            time.sleep(2)
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: _safe_terminate(ctx, session_id))
    state = _poll_session_state(ctx, session_id, {"IDLE", "FAILED", "DEGRADED"}, timeout_s)
    if state != "IDLE":
        raise AssertionError(f"session {session_id} never reached IDLE, ended at {state!r}")
    return session_id


def _safe_terminate(ctx, session_id):
    athena = ctx.client("athena")
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_notebook(ctx, notebook_id):
    athena = ctx.client("athena")
    try:
        athena.delete_notebook(NotebookId=notebook_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "was not found" in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
