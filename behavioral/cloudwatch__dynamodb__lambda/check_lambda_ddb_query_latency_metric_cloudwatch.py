"""lambda-ddb-query-latency-metric-cloudwatch."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-ddb-query-latency-metric-cloudwatch"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
import os, boto3

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    resp = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": {"S": event["pk"]}},
    )
    return {"count": resp["Count"]}
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """Lambda-driven Query calls each add one SuccessfulRequestLatency sample: the metric's
    SampleCount equals the number of Query calls made."""
    table = _create_table(ctx)
    pk = f"item-{uuid.uuid4()}"
    ctx.client("dynamodb").put_item(TableName=table, Item={"pk": {"S": pk}, "val": {"S": "x"}})

    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["dynamodb:Query"], "Resource": "*"}],
    )
    fn = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table})

    n_calls = 3
    for i in range(n_calls):
        resp = _invoke(ctx, fn, {"pk": pk})
        assert resp["count"] == 1, f"Lambda-driven Query #{i} expected count=1 for pk={pk!r}, got {resp!r}"

    dims = [{"Name": "TableName", "Value": table}, {"Name": "Operation", "Value": "Query"}]
    sample_count = _poll_until(
        lambda: _metric_stat_sum(ctx, "AWS/DynamoDB", "SuccessfulRequestLatency", dims, stat="SampleCount"),
        lambda v: v >= n_calls,
        timeout_s=300,
        interval_s=20,
    )
    if not sample_count:
        raise AssertionError(
            "SuccessfulRequestLatency datapoint for Query did not appear within a 5min poll window; "
            "CloudWatch metric ingestion for DynamoDB can take several minutes."
        )
    assert sample_count == n_calls, (
        f"CloudWatch reports SuccessfulRequestLatency SampleCount={sample_count!r} for Query on "
        f"table {table!r} while exactly {n_calls} Lambda-driven Query calls were made against it; "
        f"the metric's own sample count must agree exactly with the independently-counted call "
        f"volume on the same wiring"
    )


_PREFIX = "sim2real-cwlambdadb-"
_LOGS_STMT = {
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "*",
}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _create_role(ctx: Any, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_name = _xname(ctx, "policy")
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [_LOGS_STMT, *statements]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role["Role"]["Arn"]


def _zip_code(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", src)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, src: str, env: dict[str, str] | None = None, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    code = _zip_code(src)
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                MemorySize=128,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx: Any, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed: {body}")
    return body


def _create_table(ctx: Any, wcu: int | None = None, rcu: int | None = None) -> str:
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, "tbl")
    kwargs: dict[str, Any] = dict(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    if wcu is None:
        kwargs["BillingMode"] = "PAY_PER_REQUEST"
    else:
        kwargs["ProvisionedThroughput"] = {"ReadCapacityUnits": rcu, "WriteCapacityUnits": wcu}
    ddb.create_table(**kwargs)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _metric_stat_sum(ctx: Any, namespace: str, metric_name: str, dimensions: list[dict[str, str]], stat: str = "Sum") -> float:
    cw = ctx.client("cloudwatch")
    now = datetime.now(timezone.utc)
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=now - timedelta(minutes=15),
        EndTime=now + timedelta(minutes=1),
        Period=60,
        Statistics=[stat],
    )
    return sum(dp[stat] for dp in resp.get("Datapoints", []))


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
