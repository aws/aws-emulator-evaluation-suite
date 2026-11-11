"""lambda-put-custom-metric-cloudwatch-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-put-custom-metric-cloudwatch-positive"
GROUP = "sdk-invocation"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = '''
import os
import boto3

def handler(event, context):
    cw = boto3.client("cloudwatch")
    cw.put_metric_data(
        Namespace=os.environ["METRIC_NAMESPACE"],
        MetricData=[{
            "MetricName": os.environ["METRIC_NAME"],
            "Value": 7.0,
            "Unit": "Count",
        }],
    )
    return {"ok": True}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda handler calling cloudwatch.put_metric_data produces a metric queryable via GetMetricStatistics."""
    namespace = ctx.unique_name("Sim2RealCW-")
    metric_name = "CustomMetric"

    role_arn = _create_lambda_role(
        ctx,
        policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        inline_policies=[
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"}],
            }
        ],
    )
    name = _create_function(
        ctx,
        role_arn,
        _HANDLER_SRC,
        env={"METRIC_NAMESPACE": namespace, "METRIC_NAME": metric_name},
    )

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=b"{}")
    assert resp.get("FunctionError") is None, f"unexpected invocation error: {resp.get('FunctionError')}"

    cw = ctx.client("cloudwatch")
    now = datetime.now(timezone.utc)

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=10),
            EndTime=now + timedelta(minutes=2),
            Period=300,
            Statistics=["Sum"],
        )["Datapoints"]

    datapoints = _poll_until(probe, lambda dp: len(dp) > 0, timeout_s=240.0, interval_s=10.0)
    if not datapoints:
        raise AssertionError(
            "custom metric never landed in CloudWatch within 4 minutes; this is CloudWatch metric "
            "ingestion latency, not a behavioral failure of the put_metric_data call itself"
        )
    total = sum(dp["Sum"] for dp in datapoints)
    assert abs(total - 7.0) < 0.01, f"expected metric Sum==7.0, got {total}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


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
