"""lambda-duration-metric-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-duration-metric-positive"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda", "logs"]

_HANDLER_SRC = """
import time as _time

def handler(event, context):
    _time.sleep(1.0)
    return {"slept": True}
"""


# timing:real-time — metric: 46 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Lambda invocation duration is recorded as the AWS/Lambda Duration metric."""
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(ctx, role_arn, _HANDLER_SRC, timeout=10)

    start = datetime.now(timezone.utc) - timedelta(minutes=1)

    lam = ctx.client("lambda")
    for _ in range(2):
        resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse")
        assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
        assert resp.get("FunctionError") is None, f"expected no FunctionError, got {resp.get('FunctionError')}"

    max_duration_ms = _poll_metric_max(
        ctx,
        namespace="AWS/Lambda",
        metric_name="Duration",
        dimensions=[{"Name": "FunctionName", "Value": fn_name}],
        start=start,
        min_value=700.0,
        timeout_s=300.0,
        interval_s=15.0,
    )
    if max_duration_ms is None:
        raise AssertionError(
            "AWS/Lambda Duration metric did not appear (or never reflected the induced "
            "1s sleep) within 300s poll window; CloudWatch ingestion latency exceeded budget"
        )
    assert max_duration_ms >= 700.0, f"expected Duration max >= 700ms, got {max_duration_ms}"


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
            # IAM role propagation is eventually consistent: Lambda may not yet be able
            # to assume a role that was just created, so retry until it can.
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


def _poll_metric_max(
    ctx,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    start: datetime,
    min_value: float,
    timeout_s: float = 300.0,
    interval_s: float = 15.0,
) -> float | None:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    best = None
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
            Period=60,
            Statistics=["Maximum"],
        )
        datapoints = resp.get("Datapoints", [])
        if datapoints:
            candidate = max(dp["Maximum"] for dp in datapoints)
            best = candidate if best is None else max(best, candidate)
            if best >= min_value:
                return best
        time.sleep(interval_s)
    return best


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
