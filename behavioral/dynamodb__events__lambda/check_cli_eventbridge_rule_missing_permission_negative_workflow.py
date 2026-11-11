"""cli-eventbridge-rule-missing-permission-negative-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-eventbridge-rule-missing-permission-negative-workflow"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule targeting a Lambda function that grants events.amazonaws.com no invoke permission never delivers a
    matching put-events entry (EventBridge reports no error to the publisher); after add-permission the same rule
    and target deliver the next entry.
    """
    require_tools("aws")

    role_name, role_arn = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    handler_code = (
        "import json\n"
        "def handler(event, context):\n"
        "    print('MARKER_EVENT_RECEIVED:' + json.dumps(event.get('detail', {})))\n"
        "    return {'ok': True}\n"
    )
    fn_arn = _create_function(ctx, fn_name, role_arn, handler_code)

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    source_val = ctx.unique_name("sim2real.nogrant.")
    _run_aws(
        ctx,
        "events",
        "put-rule",
        "--name",
        rule_name,
        "--event-pattern",
        json.dumps({"source": [source_val]}),
        "--tags",
        json.dumps(_mgmt_tags_kv()),
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "events", "delete-rule", "--name", rule_name, check=False))

    # NOTE: deliberately skip `aws lambda add-permission` here — the resource policy that would
    # let events.amazonaws.com invoke the function is never granted.
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

    blocked_token = ctx.unique_name("blocked-marker-")
    entries = [
        {
            "Source": source_val,
            "DetailType": "sim2real-test",
            "Detail": json.dumps({"marker": blocked_token}),
        }
    ]
    _run_aws(ctx, "events", "put-events", "--entries", json.dumps(entries))

    delivered = _poll_logs_for_marker(ctx, fn_name, blocked_token, timeout_s=45.0, interval_s=5.0)
    assert not delivered, (
        f"marker {blocked_token} was delivered despite the target lacking lambda:InvokeFunction "
        "resource policy for events.amazonaws.com"
    )

    # Positive control: grant the permission and confirm the SAME rule/target then delivers.
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
    control_token = ctx.unique_name("control-marker-")
    control_entries = [
        {
            "Source": source_val,
            "DetailType": "sim2real-test",
            "Detail": json.dumps({"marker": control_token}),
        }
    ]
    _run_aws(ctx, "events", "put-events", "--entries", json.dumps(control_entries))
    control_delivered = _poll_logs_for_marker(ctx, fn_name, control_token, timeout_s=90.0, interval_s=5.0)
    assert control_delivered, "positive control: expected delivery once lambda:AddPermission was granted"


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


def _mgmt_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _mgmt_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]


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
        Tags=_mgmt_tags_kv(),
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
        Tags=_mgmt_tags(),
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


def _poll_logs_for_marker(ctx, function_name, marker, timeout_s=90.0, interval_s=5.0):
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
        except logs.exceptions.ResourceNotFoundException:
            time.sleep(interval_s)
            continue
        for event in resp.get("events", []):
            if marker in event.get("message", ""):
                return True
        time.sleep(interval_s)
    return False


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
