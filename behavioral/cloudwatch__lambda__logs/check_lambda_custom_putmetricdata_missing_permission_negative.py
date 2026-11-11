"""lambda-custom-putmetricdata-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-custom-putmetricdata-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "lambda", "logs"]

_HANDLER_SRC = """
import os
import json
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    cw = boto3.client("cloudwatch")
    try:
        cw.put_metric_data(
            Namespace=os.environ["METRIC_NAMESPACE"],
            MetricData=[
                {
                    "MetricName": os.environ["METRIC_NAME"],
                    "Value": 1.0,
                    "Unit": "Count",
                }
            ],
        )
        return {"error_code": None}
    except ClientError as exc:
        return {"error_code": exc.response["Error"]["Code"]}
"""

_PUT_METRIC_DATA_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"}],
}


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Handler's cloudwatch.put_metric_data fails when the execution role lacks the permission,
    while an identical handler with the permission granted still succeeds (positive control)."""
    namespace = ctx.unique_name("Sim2Real/BehavioralPermBoundary/")

    control_role_arn = _create_lambda_role(ctx, {"allow-put-metric-data": _PUT_METRIC_DATA_POLICY})
    test_role_arn = _create_lambda_role(ctx, None)

    control_metric = "ControlMetric"
    test_metric = "DeniedMetric"

    control_fn = _create_function(
        ctx,
        control_role_arn,
        _HANDLER_SRC,
        env={"METRIC_NAMESPACE": namespace, "METRIC_NAME": control_metric},
    )
    test_fn = _create_function(
        ctx,
        test_role_arn,
        _HANDLER_SRC,
        env={"METRIC_NAMESPACE": namespace, "METRIC_NAME": test_metric},
    )

    start = datetime.now(timezone.utc) - timedelta(minutes=1)
    lam = ctx.client("lambda")

    # The one thing broken: role WITHOUT cloudwatch:PutMetricData is denied.
    test_resp = lam.invoke(FunctionName=test_fn, InvocationType="RequestResponse")
    assert test_resp.get("FunctionError") is None, (
        f"denied-role invoke of {test_fn} raised a FunctionError, expected a handled "
        f"ClientError returned as payload: {test_resp.get('FunctionError')!r}"
    )
    test_payload = json.loads(test_resp["Payload"].read())
    assert test_payload.get("error_code") == "AccessDenied", (
        f"test handler (role WITHOUT cloudwatch:PutMetricData) expected error_code "
        f"'AccessDenied', got {test_payload.get('error_code')!r}"
    )

    # Positive control: role WITH cloudwatch:PutMetricData succeeds and the metric lands.
    control_resp = lam.invoke(FunctionName=control_fn, InvocationType="RequestResponse")
    assert control_resp.get("FunctionError") is None, (
        f"control invoke of {control_fn} raised a FunctionError, expected none: "
        f"{control_resp.get('FunctionError')!r}"
    )
    control_payload = json.loads(control_resp["Payload"].read())
    assert control_payload == {"error_code": None}, (
        f"control handler (role WITH cloudwatch:PutMetricData) expected "
        f"{{'error_code': None}}, got {control_payload!r}"
    )

    control_value = _poll_metric_max(
        ctx,
        namespace=namespace,
        metric_name=control_metric,
        start=start,
        min_value=1.0,
        timeout_s=240.0,
        interval_s=2.0,
    )
    if control_value is None:
        raise AssertionError(
            f"control metric {namespace}/{control_metric} did not appear within 240s poll window; "
            "cannot validate the positive-control side of this negative check in the time budget"
        )
    assert control_value == 1.0, (
        f"control metric {namespace}/{control_metric} expected Maximum 1.0, got {control_value!r}"
    )

    # Absence by contrast: the control datapoint, put after the denied call, has landed.
    denied_value = _metric_max(ctx.client("cloudwatch"), namespace, test_metric, start)
    assert denied_value is None, f"expected no datapoint for denied metric, got {denied_value}"


# ===== helpers =====

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


def _create_lambda_role(ctx, inline_policies: dict[str, dict] | None) -> str:
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
    # No fixed propagation wait: _create_function already retries CreateFunction on
    # InvalidParameterValueException (the "role cannot be assumed" error IAM propagation lag
    # produces), which is the bounded, deadline-driven form of the same wait.
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


def _poll_metric_max(
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
    best = None
    while time.monotonic() < deadline:
        candidate = _metric_max(cw, namespace, metric_name, start)
        if candidate is not None:
            best = candidate if best is None else max(best, candidate)
            if best >= min_value:
                return best
        time.sleep(interval_s)
    return best


def _metric_max(cw, namespace: str, metric_name: str, start: datetime) -> float | None:
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Maximum"],
    )
    datapoints = resp.get("Datapoints", [])
    return max(dp["Maximum"] for dp in datapoints) if datapoints else None


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
