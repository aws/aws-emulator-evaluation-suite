"""lambda-cloudwatch-getmetricstatistics-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-cloudwatch-getmetricstatistics-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "lambda", "logs"]

_HANDLER_SRC = """
import json
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

def handler(event, context):
    cw = boto3.client("cloudwatch")
    now = datetime.now(timezone.utc)
    try:
        resp = cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Invocations",
            StartTime=now - timedelta(hours=1),
            EndTime=now,
            Period=3600,
            Statistics=["Sum"],
        )
        return {"error_code": None, "datapoint_count": len(resp.get("Datapoints", []))}
    except ClientError as exc:
        return {"error_code": exc.response["Error"]["Code"]}
"""

_GET_METRIC_STATS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "cloudwatch:GetMetricStatistics", "Resource": "*"}],
}


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Handler's cloudwatch.get_metric_statistics call is denied without the read permission,
    while an identical handler whose role has the permission still succeeds (positive control)."""
    control_role_arn = _create_lambda_role(ctx, {"allow-get-metric-stats": _GET_METRIC_STATS_POLICY})
    test_role_arn = _create_lambda_role(ctx, None)

    control_fn = _create_function(ctx, control_role_arn, _HANDLER_SRC)
    test_fn = _create_function(ctx, test_role_arn, _HANDLER_SRC)

    lam = ctx.client("lambda")

    # Positive control: role WITH cloudwatch:GetMetricStatistics succeeds.
    control_resp = lam.invoke(FunctionName=control_fn, InvocationType="RequestResponse")
    assert control_resp.get("FunctionError") is None, (
        f"control invoke must not raise inside the handler; got FunctionError={control_resp.get('FunctionError')!r}"
    )
    control_payload = json.loads(control_resp["Payload"].read())
    assert control_payload.get("error_code") is None, (
        f"control role has cloudwatch:GetMetricStatistics, so the call must succeed; "
        f"got error_code={control_payload.get('error_code')!r}"
    )
    assert "datapoint_count" in control_payload, (
        f"a successful GetMetricStatistics call must report a datapoint_count; got {control_payload!r}"
    )

    # The one thing broken: role WITHOUT cloudwatch:GetMetricStatistics is denied.
    test_resp = lam.invoke(FunctionName=test_fn, InvocationType="RequestResponse")
    assert test_resp.get("FunctionError") is None, (
        f"test invoke must not raise inside the handler (the denial must be caught and returned, "
        f"not crash it); got FunctionError={test_resp.get('FunctionError')!r}"
    )
    test_payload = json.loads(test_resp["Payload"].read())
    assert test_payload.get("error_code") == "AccessDenied", (
        f"test role lacks cloudwatch:GetMetricStatistics, so the call must be refused with exactly "
        f"AccessDenied; got error_code={test_payload.get('error_code')!r}"
    )
    assert "datapoint_count" not in test_payload, (
        f"a denied GetMetricStatistics call must not report a datapoint_count; got {test_payload!r}"
    )

    # The denial must be scoped to the test role, not a wider/transient outage: the identical
    # control call, re-issued after the negative, must still succeed.
    recheck_resp = lam.invoke(FunctionName=control_fn, InvocationType="RequestResponse")
    assert recheck_resp.get("FunctionError") is None, (
        f"control recheck invoke must not raise; got FunctionError={recheck_resp.get('FunctionError')!r}"
    )
    recheck_payload = json.loads(recheck_resp["Payload"].read())
    assert recheck_payload.get("error_code") is None, (
        f"the control role must still succeed after the test role's denial, proving the denial was "
        f"scoped to the test role and not a global/transient failure; got "
        f"error_code={recheck_payload.get('error_code')!r}"
    )


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    for policy_name, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    # Role propagation delay is not slept here: _create_function's bounded retry on
    # InvalidParameterValueException below is what actually waits it out.
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
        Tags={"sim2real": CHECK},
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    # Bounded retry on InvalidParameterValueException: this is the observable symptom of IAM
    # role-propagation lag, and doubles as the wait for it -- no separate unconditional sleep.
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
