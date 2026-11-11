"""cli-scheduler-update-schedule-changes-target."""
from __future__ import annotations

import io
import json
import subprocess
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-scheduler-update-schedule-changes-target"
GROUP = "cli-roundtrip"
SERVICES = ["lambda", "scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """`aws scheduler update-schedule` repointing Target.Arn from function A to function B
    causes subsequent firings to invoke only B: A stops receiving new invocations after the
    update, and B starts receiving them."""
    require_tools("aws")

    lambda_role_arn = _create_lambda_role(ctx)
    fn_a = _create_lambda_function(ctx, lambda_role_arn, "a")
    fn_b = _create_lambda_function(ctx, lambda_role_arn, "b")
    scheduler_role_arn = _create_scheduler_role(ctx, [fn_a["arn"], fn_b["arn"]])

    marker_a = ctx.unique_name("sim2real-phasea-")
    marker_b = ctx.unique_name("sim2real-phaseb-")
    schedule_name = ctx.unique_name("sim2real-behav-sched-")
    target_a = {
        "Arn": fn_a["arn"],
        "RoleArn": scheduler_role_arn,
        "Input": json.dumps({"tag": marker_a}),
    }
    t0_ms = _now_ms()
    _run_aws_with_role_propagation_retry(
        ctx,
        "scheduler",
        "create-schedule",
        "--name",
        schedule_name,
        "--schedule-expression",
        "rate(1 minute)",
        "--flexible-time-window",
        "Mode=OFF",
        "--target",
        json.dumps(target_a),
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "scheduler", "delete-schedule", "--name", schedule_name, check=False))

    # Wait for the first firing against function A before switching the target.
    a_events_before = _poll_for_marker(ctx, fn_a["name"], marker_a, t0_ms, timeout_s=90.0)
    assert a_events_before, f"expected {fn_a['name']} to be invoked with the original target"

    target_b = {
        "Arn": fn_b["arn"],
        "RoleArn": scheduler_role_arn,
        "Input": json.dumps({"tag": marker_b}),
    }
    t_update_ms = _now_ms()
    _run_aws_with_role_propagation_retry(
        ctx,
        "scheduler",
        "update-schedule",
        "--name",
        schedule_name,
        "--schedule-expression",
        "rate(1 minute)",
        "--flexible-time-window",
        "Mode=OFF",
        "--target",
        json.dumps(target_b),
    )

    # B must start receiving invocations after the update.
    b_events_after = _poll_for_marker(ctx, fn_b["name"], marker_b, t_update_ms, timeout_s=90.0)
    assert b_events_after, f"expected {fn_b['name']} to be invoked with the new target after update"
    t_confirmed_ms = _now_ms()

    # Stop the schedule immediately once we have proof B fired, then check A saw nothing new
    # since the update was issued (the old target must not keep firing after the switch).
    _run_aws(ctx, "scheduler", "delete-schedule", "--name", schedule_name, check=False)
    a_events_after = _poll_for_marker(
        ctx, fn_a["name"], marker_a, t_update_ms, timeout_s=5.0, interval_s=1.0
    )
    assert not a_events_after, (
        f"function A received {len(a_events_after)} invocation(s) after the target was "
        f"switched away from it at {t_update_ms}; last seen at {t_confirmed_ms}"
    )

    # The delete above must actually be gone, not just quiesced: an independent read 404s,
    # and a mutation against the dead name is rejected with the same specific not-found code.
    get_proc = _run_shell(
        ctx, ["aws", "--output", "json", "scheduler", "get-schedule", "--name", schedule_name],
        check=False,
    )
    code, message = _cli_error(get_proc, "GetSchedule")
    assert code == "ResourceNotFoundException", (
        f"expected get-schedule on the deleted schedule to 404 with ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Schedule {schedule_name} does not exist.", (
        f"unexpected GetSchedule not-found message: {message!r}"
    )
    update_proc = _run_shell(
        ctx,
        [
            "aws", "--output", "json", "scheduler", "update-schedule",
            "--name", schedule_name,
            "--schedule-expression", "rate(1 minute)",
            "--flexible-time-window", "Mode=OFF",
            "--target", json.dumps(target_b),
        ],
        check=False,
    )
    code, message = _cli_error(update_proc, "UpdateSchedule")
    assert code == "ResourceNotFoundException", (
        f"expected update-schedule on the deleted schedule to be rejected with ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Schedule {schedule_name} does not exist.", (
        f"unexpected UpdateSchedule not-found message: {message!r}"
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


def _cli_error(proc, operation):
    """The (code, message) of the aws CLI error for ``operation``; raises if the call succeeded."""
    if proc.returncode == 0:
        raise AssertionError(f"{operation} was expected to fail but succeeded: {proc.stdout[-500:]!r}")
    prefix = "An error occurred ("
    for line in proc.stderr.splitlines():
        idx = line.find(prefix)
        if idx != -1 and f"when calling the {operation} operation: " in line:
            code = line[idx + len(prefix):line.index(")", idx)]
            return code, line.split(f"when calling the {operation} operation: ", 1)[1]
    raise AssertionError(f"{operation} failed without an AWS error line: {proc.stderr[-500:]!r}")


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
