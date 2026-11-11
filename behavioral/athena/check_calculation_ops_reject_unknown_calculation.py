"""calculation-ops-reject-unknown-calculation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculation-ops-reject-unknown-calculation"
GROUP = 'error-semantics'
SERVICES = ['athena']


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_all_reject(cases, expected):
    """Assert every (label, callable) in *cases* fails with exactly *expected* (code, message),
    running all cases first so one run reports every deviation."""
    actual = {label: _error(fn) for label, fn in cases}
    deviations = {label: err for label, err in actual.items() if err != expected}
    assert not deviations, f"expected {expected} from every call; deviations: {deviations}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get/GetStatus/GetCode/StopCalculationExecution succeed on a real calculation but reject an
    unknown calculation id with InvalidRequestException "Not authorized to make this request."."""
    athena = ctx.client("athena")

    role_arn = _iam_role_for_spark(ctx)
    workgroup = _spark_workgroup(ctx, role_arn)
    session_id = _start_spark_session(ctx, workgroup, role_arn, timeout_s=150)

    real_calc_id = athena.start_calculation_execution(SessionId=session_id, CodeBlock="1 + 1")[
        "CalculationExecutionId"
    ]
    state = _poll_calc_state(ctx, real_calc_id, {"COMPLETED", "FAILED", "CANCELED"}, timeout_s=60)
    assert state == "COMPLETED", f"positive-control calculation never COMPLETED, ended at {state!r}"

    # Positive control: the three reads succeed against the real id.
    got = athena.get_calculation_execution(CalculationExecutionId=real_calc_id)
    assert got["CalculationExecutionId"] == real_calc_id, (
        f"GetCalculationExecution: expected {real_calc_id}, got {got.get('CalculationExecutionId')!r}"
    )
    status = athena.get_calculation_execution_status(CalculationExecutionId=real_calc_id)
    assert status["Status"]["State"] == "COMPLETED", (
        f"GetCalculationExecutionStatus: expected COMPLETED, got {status['Status']['State']!r}"
    )
    code = athena.get_calculation_execution_code(CalculationExecutionId=real_calc_id)
    assert code["CodeBlock"] == "1 + 1", (
        f"GetCalculationExecutionCode: expected '1 + 1', got {code.get('CodeBlock')!r}"
    )

    # Stop needs a calculation still in flight; stopping a COMPLETED one is a different contract.
    stop_calc_id = athena.start_calculation_execution(
        SessionId=session_id, CodeBlock="import time\ntime.sleep(60)\n"
    )["CalculationExecutionId"]
    in_flight = {"CREATING", "CREATED", "QUEUED", "RUNNING"}
    running_state = _poll_calc_state(
        ctx, stop_calc_id, in_flight | {"COMPLETED", "FAILED", "CANCELED", "CANCELING"}, timeout_s=45,
        interval_s=1.0,
    )
    assert running_state in in_flight, (
        f"stop positive-control calculation was not in flight before the stop, at {running_state!r}"
    )
    athena.stop_calculation_execution(CalculationExecutionId=stop_calc_id)  # must not raise

    missing_calc = "00000000-0000-0000-0000-000000000003"
    _assert_all_reject(
        [
            ("GetCalculationExecution", lambda: athena.get_calculation_execution(CalculationExecutionId=missing_calc)),
            (
                "GetCalculationExecutionStatus",
                lambda: athena.get_calculation_execution_status(CalculationExecutionId=missing_calc),
            ),
            (
                "GetCalculationExecutionCode",
                lambda: athena.get_calculation_execution_code(CalculationExecutionId=missing_calc),
            ),
            (
                "StopCalculationExecution",
                lambda: athena.stop_calculation_execution(CalculationExecutionId=missing_calc),
            ),
        ],
        # AWS answers an unknown calculation id with its generic authorization refusal.
        ("InvalidRequestException", "Not authorized to make this request."),
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    if ctx.region != "us-east-1":  # S3 rejects a LocationConstraint equal to its own default region
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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
    bucket = _s3_output_bucket(ctx)
    athena.create_work_group(
        Name=name,
        Configuration={
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-spark-results/"},
        },
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    return name


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the check's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the check's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_session_state(ctx, session_id, target_states, timeout_s, interval_s=1.5):
    athena = ctx.client("athena")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"session {session_id} reaching {sorted(target_states)}: the run "
                           "budget ended first; not graded")
    return state


def _start_spark_session(ctx, workgroup, role_arn, timeout_s=150):
    athena = ctx.client("athena")
    engine_config = {"CoordinatorDpuSize": 1, "MaxConcurrentDpus": 2, "DefaultExecutorDpuSize": 1}
    session_id = None
    last_err = None
    # Role propagation into Athena is not observable, so StartSession itself is retried.
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            session_id = athena.start_session(
                WorkGroup=workgroup, ExecutionRole=role_arn, EngineConfiguration=engine_config,
            )["SessionId"]
            break
        except ClientError as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("dpu", "capacity", "quota", "limit")):
                raise AssertionError(f"Spark session capacity unavailable: {exc}") from exc
            last_err = exc
            if time.monotonic() + 2.0 >= deadline:
                break
            time.sleep(2.0)
    if session_id is None and _budget_spent(ctx):
        raise TimeoutError("StartSession succeeding past role propagation: the run budget ended "
                           "first; not graded")
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (role propagation?): {last_err}")
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


def _poll_calc_state(ctx, calc_id, target_states, timeout_s, interval_s=1.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    state = None
    while time.monotonic() < deadline:
        state = athena.get_calculation_execution_status(CalculationExecutionId=calc_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"calculation {calc_id} reaching {sorted(target_states)}: the run "
                           "budget ended first; not graded")
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
