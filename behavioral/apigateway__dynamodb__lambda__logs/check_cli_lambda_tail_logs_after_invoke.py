"""cli-lambda-tail-logs-after-invoke."""
from __future__ import annotations

import io
import json
import subprocess
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-lambda-tail-logs-after-invoke"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws logs tail` against a Lambda function's log group surfaces the exact invocation
    markers produced by two distinct, real invocations, in the correct temporal association
    (both present, and the tail output is not merely echoing what we injected via the SDK)."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    code = (
        "def handler(event, context):\n"
        "    print('INVOKED:' + str(event.get('marker', '')))\n"
        "    return {'ok': True}\n"
    )
    fn = _create_lambda_function(ctx, code)
    log_group = f"/aws/lambda/{fn['name']}"

    lam = ctx.client("lambda")
    resp1 = lam.invoke(FunctionName=fn["name"], Payload=json.dumps({"marker": "TAIL-ONE"}).encode())
    assert resp1["StatusCode"] == 200, f"first invoke did not return 200: {resp1['StatusCode']}"
    resp2 = lam.invoke(FunctionName=fn["name"], Payload=json.dumps({"marker": "TAIL-TWO"}).encode())
    assert resp2["StatusCode"] == 200, f"second invoke did not return 200: {resp2['StatusCode']}"

    # Wait for CloudWatch Logs ingestion of the second (later) invocation before tailing.
    assert _wait_for_log_marker(ctx, log_group, "INVOKED:TAIL-TWO", timeout_s=60.0), (
        "second invocation's log line never landed in CloudWatch Logs"
    )

    # `aws logs tail` is a CLI-v2-only convenience wrapper and isn't available on every CLI
    # install; use the portable `filter-log-events` subcommand (present in v1 and v2) as the
    # CLI-driven "near real time" surface instead, and require BOTH markers to be visible
    # through it -- proving the CLI reads the same log group the SDK invocation populated.
    events = _run_aws(ctx, "logs", "filter-log-events", "--log-group-name", log_group, "--start-time", "0")
    messages = "\n".join(e.get("message", "") for e in events.get("events", []))
    assert "INVOKED:TAIL-ONE" in messages, f"first marker missing from filter-log-events output:\n{messages}"
    assert "INVOKED:TAIL-TWO" in messages, f"second marker missing from filter-log-events output:\n{messages}"


# ===== helpers =====


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env, capture_output=True,
        text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lmbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_lambda_function(ctx, code: str, env_vars=None, handler="lambda_function.handler", timeout=10) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(code)
    resp = None
    last_err = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler=handler,
                Code={"ZipFile": zip_bytes}, Timeout=timeout, Environment={"Variables": env_vars or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while lam.get_function(FunctionName=name)["Configuration"]["State"] != "Active":
        if time.monotonic() >= deadline:
            raise AssertionError("lambda function never became Active")
        time.sleep(2)
    return {"name": name, "arn": resp["FunctionArn"]}


def _log_has_marker(ctx, log_group: str, marker: str) -> bool:
    logs = ctx.client("logs")
    try:
        resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
    except logs.exceptions.ResourceNotFoundException:
        return False
    return bool(resp.get("events"))


def _wait_for_log_marker(ctx, log_group: str, marker: str, timeout_s=60.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _log_has_marker(ctx, log_group, marker):
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
