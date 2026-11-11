"""lambda-invocation-logs-appear-in-cloudwatch-logs."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-invocation-logs-appear-in-cloudwatch-logs"
GROUP = "logs-delivery"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = '''
import os

def handler(event, context):
    print(f"MARKER::{os.environ['MARKER']}")
    return {"ok": True}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Invoking a Lambda function delivers log events containing its output to CloudWatch Logs."""
    marker = ctx.unique_name("marker-")

    role_arn = _create_lambda_role(
        ctx, policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    )
    name = _create_function(ctx, role_arn, _HANDLER_SRC, env={"MARKER": marker})

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=b"{}")
    assert resp.get("FunctionError") is None

    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{name}"
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    def probe():
        try:
            return logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')["events"]
        except logs.exceptions.ResourceNotFoundException:
            return []

    events = _poll_until(
        probe, lambda evs: len(evs) > 0, timeout_s=90.0, interval_s=5.0,
        description=f"log events containing marker {marker!r} in {log_group}",
    )
    assert events, f"no log events containing marker {marker!r} appeared in {log_group}"
    assert any(marker in e["message"] for e in events)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _zip_bytes(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_arns=None, inline_policies=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwlam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for arn in policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    for i, doc in enumerate(inline_policies or []):
        pname = f"inline-{i}"
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda p=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=p))
    return role_arn


def _create_function(
    ctx,
    role_arn: str,
    code_source: str,
    handler: str = "lambda_function.handler",
    timeout: int = 30,
    memory: int = 128,
    env: dict[str, str] | None = None,
    reserved_concurrency: int | None = None,
) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cwlam-fn-")
    code_bytes = _zip_bytes("lambda_function.py", code_source)
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": code_bytes},
        Timeout=timeout,
        MemorySize=memory,
        Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3.0)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    if reserved_concurrency is not None:
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=reserved_concurrency)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
