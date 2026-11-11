"""lambda-duration-metric-recorded-cloudwatch."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-duration-metric-recorded-cloudwatch"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = '''
import time

def handler(event, context):
    time.sleep(2)
    return {"ok": True}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda invocation duration is recorded and retrievable as the AWS/Lambda Duration metric."""
    role_arn = _create_lambda_role(
        ctx, policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    )
    name = _create_function(ctx, role_arn, _HANDLER_SRC, timeout=30)

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=b"{}")
    assert resp.get("FunctionError") is None

    cw = ctx.client("cloudwatch")
    now = datetime.now(timezone.utc)

    def probe():
        return cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Duration",
            Dimensions=[{"Name": "FunctionName", "Value": name}],
            StartTime=now - timedelta(minutes=10),
            EndTime=now + timedelta(minutes=2),
            Period=300,
            Statistics=["Maximum"],
        )["Datapoints"]

    datapoints = _poll_until(
        probe, lambda dp: len(dp) > 0, timeout_s=240.0, interval_s=10.0,
        label=(
            "the AWS/Lambda Duration metric to land for this function (CloudWatch built-in "
            "metric ingestion has documented multi-minute latency)"
        ),
    )
    units = {dp["Unit"] for dp in datapoints}
    assert units == {"Milliseconds"}, f"expected AWS/Lambda Duration unit Milliseconds, got {units}"
    max_duration_ms = max(dp["Maximum"] for dp in datapoints)
    # handler sleeps 2s -> duration must reflect that sleep, and stay well under the 30s timeout.
    assert 1900.0 <= max_duration_ms <= 15000.0, f"unexpected Duration Maximum={max_duration_ms}ms"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, label="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {label}; last observed value was {last!r}"
    )


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
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
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
