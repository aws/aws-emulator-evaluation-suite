"""cli-eventbridge-scheduled-rule-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-eventbridge-scheduled-rule-workflow"
GROUP = "cli-workflow"
SERVICES = ["dynamodb", "events", "lambda"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule-expression rule created with the AWS CLI invokes its Lambda target at least twice, counted as
    distinct "REPORT RequestId" lines in the function's log within the bounded wait.
    """
    require_tools("aws")

    role_name, role_arn = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    handler_code = (
        "import time\n"
        "def handler(event, context):\n"
        "    print('MARKER_SCHEDULED_TICK:' + str(time.time()))\n"
        "    return {'ok': True}\n"
    )
    fn_arn = _create_function(ctx, fn_name, role_arn, handler_code)

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    _run_aws(
        ctx,
        "events",
        "put-rule",
        "--name",
        rule_name,
        "--schedule-expression",
        "rate(1 minute)",
        "--state",
        "ENABLED",
        "--tags",
        "Key=sim2real,Value=1",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "events", "delete-rule", "--name", rule_name, check=False))

    account_id = _account_id(ctx)
    rule_arn = f"arn:aws:events:{ctx.region}:{account_id}:rule/{rule_name}"

    _run_aws(
        ctx,
        "lambda",
        "add-permission",
        "--function-name",
        fn_name,
        "--statement-id",
        "AllowEventBridgeInvoke",
        "--action",
        "lambda:InvokeFunction",
        "--principal",
        "events.amazonaws.com",
        "--source-arn",
        rule_arn,
    )

    _run_aws(
        ctx,
        "events",
        "put-targets",
        "--rule",
        rule_name,
        "--targets",
        json.dumps([{"Id": "1", "Arn": fn_arn}]),
    )
    ctx.on_cleanup(
        lambda: _run_aws(ctx, "events", "remove-targets", "--rule", rule_name, "--ids", "1", check=False)
    )

    # Schedules fire on wall-clock minute boundaries (see EventBridge scheduled rules docs), so
    # observing 2 distinct invocations legitimately needs up to a few minutes of bounded polling.
    count = _poll_invocation_count(ctx, fn_name, min_count=2, timeout_s=280.0, interval_s=15.0)
    assert count >= 2, f"expected >=2 periodic invocations from the scheduled rule, saw {count}"


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


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _make_zip_bytes(handler_code: str) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_statements=None):
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
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if inline_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _create_function(ctx, name, role_arn, handler_code, env=None, timeout=30):
    lam = ctx.client("lambda")
    zip_bytes = _make_zip_bytes(handler_code)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real": "1"},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    deadline = time.monotonic() + 60
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            fn_arn = resp["FunctionArn"]
            break
        except ClientError as e:
            last_err = e
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    if fn_arn is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_arn


def _poll_invocation_count(ctx, function_name, min_count=2, timeout_s=280.0, interval_s=15.0):
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    count = 0
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
        except logs.exceptions.ResourceNotFoundException:
            time.sleep(interval_s)
            continue
        count = sum(1 for e in resp.get("events", []) if "REPORT RequestId" in e.get("message", ""))
        if count >= min_count:
            return count
        time.sleep(interval_s)
    return count


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
