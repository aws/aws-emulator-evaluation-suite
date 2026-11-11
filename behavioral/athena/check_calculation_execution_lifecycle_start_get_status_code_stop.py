"""calculation-execution-lifecycle-start-get-status-code-stop."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculation-execution-lifecycle-start-get-status-code-stop"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A calculation on an IDLE session COMPLETES with its CodeBlock retrievable, and a RUNNING
    Spark job stopped via StopCalculationExecution never COMPLETES; the list reflects both states."""
    athena = ctx.client("athena")
    # The CANCELING -> CANCELED poll at the end is the longest, most variable step; it gets
    # whatever remains of the 300s per-check budget rather than a fixed bound.
    run_start = time.monotonic()
    TOTAL_BUDGET_S = 295.0  # stay safely under the harness's 300s hard cap
    FINAL_CALL_MARGIN_S = 10.0  # reserve for the trailing list_calculation_executions check

    role_arn = _iam_role_for_spark(ctx)
    workgroup = _spark_workgroup(ctx, role_arn)
    # Session start to IDLE takes well under a minute.
    session_id = _start_spark_session(ctx, workgroup, role_arn, timeout_s=90)

    code_block = "1 + 1"
    calc_id = athena.start_calculation_execution(SessionId=session_id, CodeBlock=code_block)[
        "CalculationExecutionId"
    ]
    assert calc_id, "start_calculation_execution returned no CalculationExecutionId"

    # A trivial calculation completes in seconds; a short bound leaves budget for the cancel poll.
    state = _poll_calc_state(ctx, calc_id, {"COMPLETED", "FAILED", "CANCELED"}, timeout_s=30)
    assert state == "COMPLETED", f"calculation never COMPLETED, ended at {state!r}"

    execution = athena.get_calculation_execution(CalculationExecutionId=calc_id)
    assert execution["SessionId"] == session_id, (
        f"expected SessionId {session_id!r}, got {execution['SessionId']!r}"
    )
    assert execution["Status"]["State"] == "COMPLETED", (
        f"expected COMPLETED, got {execution['Status']['State']!r}"
    )
    # CalculationResultType is a free-form MIME-like string in the model, not an enum.
    result = execution["Result"]
    result_type = result.get("ResultType")
    assert result_type, f"COMPLETED execution has no ResultType: {result!r}"
    assert re.match(r"^\w+/[-+.\w]+$", result_type), (
        f"ResultType must be the documented MIME-like value (CalculationResultType), got {result_type!r}"
    )

    retrieved_code = athena.get_calculation_execution_code(CalculationExecutionId=calc_id)["CodeBlock"]
    assert retrieved_code == code_block, f"expected code block {code_block!r}, got {retrieved_code!r}"

    listed = {
        c["CalculationExecutionId"]: c
        for c in athena.list_calculation_executions(SessionId=session_id)["Calculations"]
    }
    assert calc_id in listed, f"{calc_id!r} missing from list_calculation_executions: {sorted(listed)!r}"
    assert listed[calc_id]["Status"]["State"] == "COMPLETED", (
        f"listed state {listed[calc_id]['Status']['State']!r}, expected COMPLETED"
    )

    # Stop is a no-op on a calculation that is not yet RUNNING, and on a driver-side sleep (no
    # Spark job to interrupt); a sleep spread across executor tasks keeps a cancelable job RUNNING.
    long_code = (
        "import time as _t\n"
        "spark.sparkContext.parallelize(range(50), 50).foreach(lambda x: _t.sleep(30))\n"
    )
    long_calc_id = athena.start_calculation_execution(SessionId=session_id, CodeBlock=long_code)[
        "CalculationExecutionId"
    ]
    running_state = _poll_calc_state(
        ctx, long_calc_id, {"RUNNING", "COMPLETED", "FAILED", "CANCELED"}, timeout_s=45, interval_s=2.0
    )
    assert running_state == "RUNNING", (
        f"long-running calculation never reached RUNNING before it could be stopped, "
        f"ended at {running_state!r}"
    )
    athena.stop_calculation_execution(CalculationExecutionId=long_calc_id)
    # CANCELING -> CANCELED can take longer than the code block itself, by a variable amount;
    # hand the poll whatever remains of the per-check budget.
    elapsed_s = time.monotonic() - run_start
    final_poll_timeout_s = max(30.0, TOTAL_BUDGET_S - FINAL_CALL_MARGIN_S - elapsed_s)
    final_state = _poll_calc_state(
        ctx, long_calc_id, {"CANCELED", "COMPLETED", "FAILED"}, timeout_s=final_poll_timeout_s, interval_s=5.0
    )
    # The interrupt may surface as CANCELED or as an execution error (FAILED); COMPLETED would
    # mean Stop had no effect.
    assert final_state in ("CANCELED", "FAILED"), (
        f"stopped calculation ended at {final_state!r}; Stop must not let it reach COMPLETED"
    )

    listed_after = {
        c["CalculationExecutionId"]: c
        for c in athena.list_calculation_executions(SessionId=session_id)["Calculations"]
    }
    assert listed_after[long_calc_id]["Status"]["State"] == final_state, (
        f"listed state {listed_after[long_calc_id]['Status']['State']!r} does not match the "
        f"{final_state!r} already observed via GetCalculationExecutionStatus"
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


def _s3_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-")
    kwargs = {}
    # S3 CreateBucket itself rejects an explicit LocationConstraint of us-east-1 -- this is the
    # API's own quirk for its default region, not an assumption about where this check runs.
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
    engine_config = {"CoordinatorDpuSize": 1, "MaxConcurrentDpus": 2, "DefaultExecutorDpuSize": 1}
    kwargs = {}
    if notebook_id:
        engine_config["AdditionalConfigs"] = {"NotebookId": notebook_id}
        kwargs["NotebookVersion"] = "Athena notebook version 1"
    # CreateRole returns before Athena can assume the role, so StartSession retries (bounded) on
    # propagation. StartSession documents Tags but refuses them for a Spark session.
    role_deadline = time.monotonic() + 60.0
    session_id = None
    while session_id is None:
        try:
            session_id = athena.start_session(
                WorkGroup=workgroup, ExecutionRole=role_arn,
                EngineConfiguration=engine_config,
                **kwargs,
            )["SessionId"]
        except ClientError as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("dpu", "capacity", "quota", "limit")):
                raise AssertionError(f"Spark session capacity unavailable: {exc}") from exc
            if time.monotonic() >= role_deadline:
                raise
            time.sleep(5)
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


def _poll_calc_state(ctx, calc_id, target_states, timeout_s, interval_s=5.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_calculation_execution_status(CalculationExecutionId=calc_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
