"""logs-metric-filter-creates-cloudwatch-metric-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "logs-metric-filter-creates-cloudwatch-metric-positive"
GROUP = "metric-filter"
SERVICES = ["cloudwatch", "lambda", "logs"]

_HANDLER_SRC = """
def handler(event, context):
    message = event.get("message", "")
    print(message)
    return {"printed": message}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A metric filter matching a Lambda function's log line emits a CloudWatch metric datapoint."""
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(ctx, role_arn, _HANDLER_SRC)
    log_group = f"/aws/lambda/{fn_name}"

    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    ctx.client("cloudwatch")

    # Prime the log group into existence with a harmless first invocation.
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b'{"message": "priming line"}')
    assert resp.get("FunctionError") is None
    _wait_log_group_exists(ctx, log_group)

    namespace = ctx.unique_name("Sim2Real/LogsMetricFilter/")
    metric_name = "ErrorLineCount"
    filter_name = ctx.unique_name("sim2real-mf-")
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern='"ERROR"',
        metricTransformations=[
            {"metricName": metric_name, "metricNamespace": namespace, "metricValue": "1"}
        ],
    )
    ctx.on_cleanup(lambda: _delete_metric_filter(ctx, log_group, filter_name))

    start = datetime.now(timezone.utc) - timedelta(minutes=1)

    resp = lam.invoke(
        FunctionName=fn_name,
        InvocationType="RequestResponse",
        Payload=b'{"message": "ERROR something failed"}',
    )
    assert resp.get("FunctionError") is None

    total = _poll_metric_sum(
        ctx,
        namespace=namespace,
        metric_name=metric_name,
        start=start,
        min_value=1.0,
        timeout_s=180.0,
        interval_s=10.0,
    )
    if total is None:
        raise AssertionError(
            f"metric filter metric {namespace}/{metric_name} did not appear within 180s poll "
            "window; log-to-metric delivery latency exceeded the check budget"
        )
    assert total >= 1.0, f"expected metric filter sum >= 1, got {total}"


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _zip_bytes(handler_source: str, filename: str = "lambda_function.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_source)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_policies: dict[str, dict] | None = None) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lg-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    for policy_name, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    return role_arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=pol_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(
    ctx,
    role_arn: str,
    handler_source: str,
    env: dict[str, str] | None = None,
    timeout: int = 15,
) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lg-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_bytes(handler_source)},
        Timeout=timeout,
        MemorySize=128,
        Tags={"sim2real:managed": "true"},
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: _delete_function(ctx, name))
    _wait_active(ctx, name)
    return name


def _delete_function(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(ctx, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} entered Failed state: {cfg.get('StateReasonCode')}")
        time.sleep(interval_s)
    raise AssertionError(f"function {name} never became Active within {timeout_s}s")


def _wait_log_group_exists(ctx, log_group: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.describe_log_groups(logGroupNamePrefix=log_group)
        if any(g["logGroupName"] == log_group for g in resp.get("logGroups", [])):
            return
        time.sleep(interval_s)
    raise AssertionError(f"log group {log_group} was never created within {timeout_s}s")


def _delete_metric_filter(ctx, log_group: str, filter_name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_metric_sum(
    ctx,
    namespace: str,
    metric_name: str,
    start: datetime,
    min_value: float,
    timeout_s: float,
    interval_s: float,
) -> float | None:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[],
            StartTime=start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
            Period=60,
            Statistics=["Sum"],
        )
        total = sum(dp["Sum"] for dp in resp.get("Datapoints", []))
        if total >= min_value:
            return total
        time.sleep(interval_s)
    return None


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
