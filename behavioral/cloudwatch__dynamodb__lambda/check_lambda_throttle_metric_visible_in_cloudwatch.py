"""lambda-throttle-metric-visible-in-cloudwatch."""

from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.config import Config
from botocore.exceptions import ClientError

CHECK = "lambda-throttle-metric-visible-in-cloudwatch"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
def handler(event, context):
    return {"ok": True}
"""
_REFUSED = 2
_THROTTLE_MESSAGE = "Rate Exceeded."
_THROTTLE_REASON = "ReservedFunctionConcurrentInvocationLimitExceeded"


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With ReservedConcurrentExecutions=0 each sequential invoke is refused (429
    TooManyRequestsException, exact message and Reason), and AWS/Lambda Throttles Sum for the
    function equals the refused count; lifting the reservation admits an invoke."""
    role_arn = _create_lambda_role(
        ctx,
        policy_arns=[
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        ],
    )
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    name = _create_function(
        ctx, role_arn, _HANDLER_SRC, timeout=30, reserved_concurrency=0
    )

    # No SDK retries: every refused request is exactly one request at the service.
    lam = ctx.client("lambda", config=Config(retries={"total_max_attempts": 1}))
    got = lam.get_function_concurrency(FunctionName=name).get("ReservedConcurrentExecutions")
    assert got == 0, f"GetFunctionConcurrency for {name} reports {got!r}, expected 0"

    for i in range(_REFUSED):
        try:
            resp = lam.invoke(FunctionName=name, Payload=b"{}")
        except ClientError as exc:
            err = exc.response
        else:
            raise AssertionError(
                f"invoke {i} of {name} with ReservedConcurrentExecutions=0 was accepted "
                f"(StatusCode {resp['StatusCode']!r}); it must be refused"
            )
        code = err["Error"]["Code"]
        message = err["Error"].get("Message")
        assert (code, message) == ("TooManyRequestsException", _THROTTLE_MESSAGE), (
            f"reserved-0 invoke {i} of {name} failed with {code!r} {message!r}, expected "
            f"TooManyRequestsException {_THROTTLE_MESSAGE!r}"
        )
        assert err.get("Reason") == _THROTTLE_REASON, (
            f"reserved-0 refusal of {name} carried Reason {err.get('Reason')!r}, expected "
            f"{_THROTTLE_REASON!r}"
        )
        status = err["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 429, f"reserved-0 refusal of {name} carried HTTP {status!r}, expected 429"

    # Lambda applies the removal asynchronously: invoke until one is admitted, counting the
    # refusals in the meantime, since each is a throttle the metric must include.
    lam.delete_function_concurrency(FunctionName=name)
    refused = _REFUSED
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            resp = lam.invoke(FunctionName=name, Payload=b"{}")
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException":
                raise
            refused += 1
            assert time.monotonic() < deadline, (
                f"invokes of {name} were still refused 120s after DeleteFunctionConcurrency"
            )
            time.sleep(2.0)
    body = json.loads(resp["Payload"].read())
    assert resp["StatusCode"] == 200 and body == {"ok": True}, (
        f"after DeleteFunctionConcurrency the invoke of {name} returned "
        f"{resp['StatusCode']!r} {body!r}"
    )

    cw = ctx.client("cloudwatch")

    def probe():
        return cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Throttles",
            Dimensions=[{"Name": "FunctionName", "Value": name}],
            StartTime=start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
            Period=300,
            Statistics=["Sum"],
        )["Datapoints"]

    datapoints = _poll_until(
        probe,
        lambda dp: sum(d["Sum"] for d in dp) >= refused,
        timeout_s=_budget_s(ctx, 240.0),
        interval_s=2.0,
        label=(
            f"the AWS/Lambda Throttles metric for this function to reach {refused} (CloudWatch "
            f"built-in metric ingestion has documented multi-minute latency)"
        ),
    )
    total = sum(dp["Sum"] for dp in datapoints)
    assert total == float(refused), (
        f"AWS/Lambda Throttles Sum for {name} is {total!r}; exactly {refused} requests were "
        f"refused and SDK retries were off"
    )

    # Independent read that the refused invokes left no side effect: only the one admitted
    # call ever ran, so Invocations must count it and no more.
    invocations = sum(
        d["Sum"]
        for d in cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Invocations",
            Dimensions=[{"Name": "FunctionName", "Value": name}],
            StartTime=start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
            Period=300,
            Statistics=["Sum"],
        )["Datapoints"]
    )
    assert invocations == 1.0, (
        f"AWS/Lambda Invocations Sum for {name} is {invocations!r}; the {refused} throttled "
        f"invokes must never have run, leaving exactly the one admitted invocation"
    )


def _budget_s(ctx, cap_s: float) -> float:
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 10 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 10.0))


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, label="condition"):
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
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
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
        ctx.on_cleanup(
            lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a)
        )
    for i, doc in enumerate(inline_policies or []):
        pname = f"inline-{i}"
        iam.put_role_policy(
            RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc)
        )
        ctx.on_cleanup(
            lambda p=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        )
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
            time.sleep(2.0)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    if reserved_concurrency is not None:
        lam.put_function_concurrency(
            FunctionName=name, ReservedConcurrentExecutions=reserved_concurrency
        )
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
