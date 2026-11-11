"""cli-put-metric-alarm-describe-lambda-workflow."""
from __future__ import annotations

import json
import subprocess
import time
import io
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-put-metric-alarm-describe-lambda-workflow"
GROUP = "cli-workflow"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`aws cloudwatch put-metric-alarm` on a Lambda Errors metric is confirmed via
    `describe-alarms` (correct namespace/metric/dimensions) and SDK-driven state transitions
    (set_alarm_state) are reflected in describe_alarms and alarm history."""
    require_tools("aws")

    role_arn = _create_lambda_role(ctx, with_logs_permission=True)
    fn_name = ctx.unique_name("sim2real-behav-alarmfn-")
    handler_code = "def handler(event, context):\n    return 'ok'\n"
    _create_function(ctx, fn_name, role_arn, handler_code)

    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    _run_aws(
        ctx,
        "cloudwatch", "put-metric-alarm",
        "--alarm-name", alarm_name,
        "--namespace", "AWS/Lambda",
        "--metric-name", "Errors",
        "--dimensions", f"Name=FunctionName,Value={fn_name}",
        "--statistic", "Sum",
        "--period", "60",
        "--evaluation-periods", "1",
        "--threshold", "1",
        "--comparison-operator", "GreaterThanOrEqualToThreshold",
        "--treat-missing-data", "notBreaching",
        "--tags", "Key=sim2real:managed,Value=true",
    )

    described = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        resp = _run_aws(ctx, "cloudwatch", "describe-alarms", "--alarm-names", alarm_name)
        alarms = resp.get("MetricAlarms", [])
        if alarms:
            described = alarms[0]
            break
        time.sleep(2)
    assert described is not None, "alarm never appeared in describe-alarms"
    assert described["Namespace"] == "AWS/Lambda", (
        f"expected namespace AWS/Lambda, got {described['Namespace']!r}"
    )
    assert described["MetricName"] == "Errors", (
        f"expected metric name Errors, got {described['MetricName']!r}"
    )
    dims = {d["Name"]: d["Value"] for d in described["Dimensions"]}
    assert dims == {"FunctionName": fn_name}, (
        f"expected dimensions {{'FunctionName': {fn_name!r}}}, got {dims!r}"
    )

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-check-forced-alarm")
    _poll_alarm_state(ctx, alarm_name, "ALARM", timeout_s=30)

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="behavioral-check-forced-ok")
    _poll_alarm_state(ctx, alarm_name, "OK", timeout_s=30)

    history = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")["AlarmHistoryItems"]
    new_states = [json.loads(h["HistoryData"])["newState"]["stateValue"] for h in history]
    assert "ALARM" in new_states, (
        f"expected a StateUpdate history entry transitioning to ALARM, got new-states: {new_states}"
    )
    assert "OK" in new_states, (
        f"expected a StateUpdate history entry transitioning to OK, got new-states: {new_states}"
    )


def _poll_alarm_state(ctx, alarm_name, expected_state, timeout_s=30):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
        last_state = alarms[0]["StateValue"] if alarms else None
        if last_state == expected_state:
            return
        time.sleep(2)
    raise AssertionError(f"alarm never reached state {expected_state!r}, last seen: {last_state!r}")


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
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, with_logs_permission: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if with_logs_permission:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    return role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for p in attached:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(ctx, name, role_arn, handler_code, handler="index.handler", timeout_s=15, env_vars=None):
    lam = ctx.client("lambda")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": _zip_bytes(handler_code)},
        Timeout=timeout_s,
        Publish=True,
        Tags={"sim2real:managed": "true"},
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    deadline = time.monotonic() + 60
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return resp["FunctionArn"]


def _wait_for_active(ctx, name, timeout_s=60):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError("function never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
