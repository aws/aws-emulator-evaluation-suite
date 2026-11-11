"""lambda-put-metric-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-put-metric-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = '''
import os
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    cw = boto3.client("cloudwatch")
    try:
        cw.put_metric_data(
            Namespace=os.environ["METRIC_NAMESPACE"],
            MetricData=[{"MetricName": os.environ["METRIC_NAME"], "Value": 1.0, "Unit": "Count"}],
        )
        return {"ok": True}
    except ClientError as err:
        return {"ok": False, "code": err.response["Error"]["Code"]}
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without cloudwatch:PutMetricData, the SDK call inside the handler fails with AccessDenied and no
    metric is recorded; the same handler code succeeds when the role has the permission (in-file control).
    """
    namespace_neg = ctx.unique_name("Sim2RealCW-neg-")
    namespace_pos = ctx.unique_name("Sim2RealCW-pos-")
    metric_name = "GuardedMetric"

    # Negative: only logging permission, no cloudwatch:PutMetricData.
    neg_role = _create_lambda_role(
        ctx, policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    )
    neg_fn = _create_function(
        ctx, neg_role, _HANDLER_SRC, env={"METRIC_NAMESPACE": namespace_neg, "METRIC_NAME": metric_name}
    )

    # Positive control: same handler code, role additionally granted cloudwatch:PutMetricData.
    pos_role = _create_lambda_role(
        ctx,
        policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        inline_policies=[
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"}],
            }
        ],
    )
    pos_fn = _create_function(
        ctx, pos_role, _HANDLER_SRC, env={"METRIC_NAMESPACE": namespace_pos, "METRIC_NAME": metric_name}
    )

    lam = ctx.client("lambda")

    neg_resp = lam.invoke(FunctionName=neg_fn, Payload=b"{}")
    assert neg_resp.get("FunctionError") is None, f"neg invoke raised: {neg_resp.get('FunctionError')}"
    neg_payload = json.loads(neg_resp["Payload"].read())
    assert neg_payload["ok"] is False, f"expected the denied call to fail, got payload {neg_payload}"
    assert neg_payload["code"] == "AccessDenied", f"expected AccessDenied, got {neg_payload['code']!r}"

    pos_resp = lam.invoke(FunctionName=pos_fn, Payload=b"{}")
    assert pos_resp.get("FunctionError") is None, f"pos invoke raised: {pos_resp.get('FunctionError')}"
    pos_payload = json.loads(pos_resp["Payload"].read())
    assert pos_payload["ok"] is True, f"expected the permitted call to succeed, got payload {pos_payload}"

    # The positive control's own success report is the SDK call's own response, not proof the
    # metric actually landed at the destination -- a target that fakes acceptance but never stores
    # metrics would still pass a check that stopped here. Read it back independently before trusting
    # the twin comparison below.
    cw = ctx.client("cloudwatch")
    pos_sum = _wait_for_metric_sum(cw, namespace_pos, metric_name, min_sum=1.0, timeout_s=150.0, interval_s=10.0)
    assert pos_sum == 1.0, f"expected exactly one recorded datapoint of value 1.0, got sum {pos_sum}"

    # The blocked call was never accepted by CloudWatch, so its absence is deterministic (not an
    # eventual-consistency race) -- a single immediate query suffices.
    now = datetime.now(timezone.utc)
    neg_datapoints = cw.get_metric_statistics(
        Namespace=namespace_neg,
        MetricName=metric_name,
        StartTime=now - timedelta(minutes=10),
        EndTime=now + timedelta(minutes=2),
        Period=300,
        Statistics=["Sum"],
    )["Datapoints"]
    assert neg_datapoints == [], f"metric should never have been recorded, found {neg_datapoints}"


def _wait_for_metric_sum(
    cw, namespace: str, metric_name: str, min_sum: float, timeout_s: float, interval_s: float
) -> float:
    deadline = time.monotonic() + timeout_s
    last_sum = 0.0
    while time.monotonic() < deadline:
        now = datetime.now(timezone.utc)
        datapoints = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=10),
            EndTime=now + timedelta(minutes=2),
            Period=300,
            Statistics=["Sum"],
        )["Datapoints"]
        last_sum = sum(dp["Sum"] for dp in datapoints)
        if last_sum >= min_sum:
            return last_sum
        time.sleep(interval_s)
    raise AssertionError(
        f"metric {namespace}/{metric_name} never reached sum {min_sum} within {timeout_s}s "
        f"(last observed sum: {last_sum})"
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
