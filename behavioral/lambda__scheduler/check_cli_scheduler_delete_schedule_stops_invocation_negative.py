"""cli-scheduler-delete-schedule-stops-invocation-negative."""
from __future__ import annotations

import io
import json
import subprocess
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-scheduler-delete-schedule-stops-invocation-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "scheduler"]

_DISPATCH_GRACE_MS = 10_000


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """After delete-schedule, GetSchedule on the deleted schedule fails with ResourceNotFoundException
    (exact message) and its target gets no new invocations, while a sibling schedule keeps firing in
    the same window."""
    require_tools("aws")

    lambda_role_arn = _create_lambda_role(ctx)
    fn_deleted = _create_lambda_function(ctx, lambda_role_arn, "del")
    fn_control = _create_lambda_function(ctx, lambda_role_arn, "ctl")
    scheduler_role_arn = _create_scheduler_role(ctx, [fn_deleted["arn"], fn_control["arn"]])

    marker_del = ctx.unique_name("sim2real-todelete-")
    marker_ctl = ctx.unique_name("sim2real-control-")
    schedule_deleted_name = ctx.unique_name("sim2real-behav-sched-del-")
    schedule_control_name = ctx.unique_name("sim2real-behav-sched-ctl-")

    t0_ms = _now_ms()
    _run_aws_with_role_propagation_retry(
        ctx, "scheduler", "create-schedule",
        "--name", schedule_deleted_name,
        "--schedule-expression", "rate(1 minute)",
        "--flexible-time-window", "Mode=OFF",
        "--target", json.dumps({
            "Arn": fn_deleted["arn"], "RoleArn": scheduler_role_arn,
            "Input": json.dumps({"tag": marker_del}),
        }),
    )
    schedule_deleted_alive = {"value": True}
    ctx.on_cleanup(
        lambda: _run_aws(ctx, "scheduler", "delete-schedule", "--name", schedule_deleted_name, check=False)
        if schedule_deleted_alive["value"] else None
    )
    _run_aws_with_role_propagation_retry(
        ctx, "scheduler", "create-schedule",
        "--name", schedule_control_name,
        "--schedule-expression", "rate(1 minute)",
        "--flexible-time-window", "Mode=OFF",
        "--target", json.dumps({
            "Arn": fn_control["arn"], "RoleArn": scheduler_role_arn,
            "Input": json.dumps({"tag": marker_ctl}),
        }),
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "scheduler", "delete-schedule", "--name", schedule_control_name, check=False))

    # Both schedules must fire at least once before we delete one of them.
    del_events_before = _poll_for_marker(ctx, fn_deleted["name"], marker_del, t0_ms, timeout_s=90.0)
    assert del_events_before, f"expected {fn_deleted['name']} to be invoked before deletion"
    ctl_events_before = _poll_for_marker(ctx, fn_control["name"], marker_ctl, t0_ms, timeout_s=90.0)
    assert ctl_events_before, f"expected {fn_control['name']} to be invoked before deletion"

    _run_aws(ctx, "scheduler", "delete-schedule", "--name", schedule_deleted_name)
    schedule_deleted_alive["value"] = False
    # The window opens once delete-schedule has returned, plus a grace for a firing dispatched
    # before the delete completed to log its invocation.
    t_delete_ms = _now_ms() + _DISPATCH_GRACE_MS

    # The deleted schedule must be gone from an independent (SDK, not CLI) read, not just
    # absent from future invocations.
    scheduler_sdk = ctx.client("scheduler")
    try:
        scheduler_sdk.get_schedule(Name=schedule_deleted_name)
    except scheduler_sdk.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"]["Message"]
        assert message == f"Schedule {schedule_deleted_name} does not exist.", (
            f"unexpected GetSchedule not-found message after delete-schedule: {message!r}"
        )
    else:
        raise AssertionError(
            f"expected get-schedule({schedule_deleted_name!r}) to raise ResourceNotFoundException "
            "after delete-schedule, but it returned a schedule"
        )

    # The control schedule (still running) must produce a NEW invocation after this point --
    # this proves the observation window is long enough to catch a real firing.
    ctl_events_after = _poll_for_marker(ctx, fn_control["name"], marker_ctl, t_delete_ms, timeout_s=120.0)
    assert ctl_events_after, "control schedule (not deleted) produced no new invocation; window too short to trust the negative"

    # Only now check the deleted schedule's target: it must have received nothing new since
    # deletion, over the exact same elapsed window we just proved is long enough.
    del_events_after = _poll_for_marker(
        ctx, fn_deleted["name"], marker_del, t_delete_ms, timeout_s=5.0, interval_s=1.0
    )
    assert not del_events_after, (
        f"deleted schedule's target received {len(del_events_after)} invocation(s) after delete-schedule"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _run_aws_with_role_propagation_retry(ctx, *args: str, timeout_s: float = 60.0, interval_s: float = 5.0):
    """IAM role trust/assume-role propagation into scheduler.amazonaws.com is eventually
    consistent — a brand-new execution role can transiently fail CreateSchedule/UpdateSchedule
    validation. Retry until the role is usable or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _run_aws(ctx, *args)
        except AssertionError as exc:
            msg = str(exc)
            if "must allow" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _now_ms() -> int:
    return int(time.time() * 1000)


def _lambda_zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


_HANDLER_CODE = (
    "import json\n"
    "def handler(event, context):\n"
    "    print('SCHED_MARKER:' + json.dumps(event))\n"
    "    return {'ok': True}\n"
)


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-lmbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_lambda_function(ctx, role_arn: str, suffix: str = "") -> dict:
    lam = ctx.client("lambda")
    func_name = ctx.unique_name(f"sim2real-behav-fn{suffix}-")
    code = _lambda_zip_bytes(_HANDLER_CODE)
    last_err = None
    fn = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            fn = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=15,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if fn is None:
        raise AssertionError(f"create_function never succeeded (IAM propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_for_function_active(ctx, func_name)
    return {"name": func_name, "arn": fn["FunctionArn"]}


def _wait_for_function_active(ctx, function_name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg.get("State") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {function_name} never became Active")


def _create_scheduler_role(ctx, target_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-schedrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": target_arns,
        }],
    }
    policy_name = ctx.unique_name("sim2real-behav-schedpolicy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _poll_for_marker(ctx, function_name: str, marker: str, start_time_ms: int, timeout_s: float = 180.0, interval_s: float = 5.0):
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(
                logGroupName=log_group,
                startTime=start_time_ms,
                filterPattern=f'"{marker}"',

            )
            if resp.get("events"):
                return resp["events"]
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(interval_s)
    return []


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
