"""lambda-ddb-batchwrite-unprocessed-items-metric."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-ddb-batchwrite-unprocessed-items-metric"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
import os, boto3
from botocore.config import Config
from botocore.exceptions import ClientError

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb", config=Config(retries={"max_attempts": 0}))
    batch_id = event["batch_id"]
    total_unprocessed = 0
    # Issue many back-to-back BatchWriteItem calls with no client-side retry and no
    # inter-call delay, from inside the same invocation (no network hop between
    # rounds), to burn through the table's banked burst/adaptive capacity fast
    # enough that some writes come back as UnprocessedItems -- or the whole call
    # is rejected outright with ProvisionedThroughputExceededException, which is
    # the same underlying throttling signal just surfaced as an exception instead
    # of a partial per-item result.
    for r in range(40):
        items = [
            {"PutRequest": {"Item": {"pk": {"S": "b-%d-%d-%s" % (r, i, batch_id)}, "val": {"S": "x"}}}}
            for i in range(25)
        ]
        try:
            resp = ddb.batch_write_item(RequestItems={table: items})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                total_unprocessed += len(items)
                break
            raise
        unprocessed = resp.get("UnprocessedItems", {}).get(table, [])
        total_unprocessed += len(unprocessed)
        if total_unprocessed > 0:
            break
    return {"unprocessed": total_unprocessed}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """Unprocessed items from a Lambda-driven BatchWriteItem call correlate with elevated ThrottledRequests in CloudWatch."""
    table = _create_table(ctx, wcu=1, rcu=1)
    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["dynamodb:BatchWriteItem"], "Resource": "*"}],
    )
    fn = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table}, timeout=60)

    # A freshly-created provisioned table starts with a full burst-capacity bank
    # (up to 300 seconds' worth of unused capacity, i.e. 300 WCU for a 1-WCU table).
    # Each invocation drives 40 rapid-fire 25-item batches (1000 WCU-worth) with no
    # inter-call delay and no client-side retry, so a handful of invocations should
    # exceed the bank and come back with UnprocessedItems.
    total_unprocessed = 0
    for i in range(30):
        resp = _invoke(ctx, fn, {"batch_id": str(i)})
        total_unprocessed += resp["unprocessed"]
        if total_unprocessed > 0:
            break
    assert total_unprocessed > 0, "expected at least one UnprocessedItem from a 1-WCU table under sustained 25-item batch bursts"

    dims = [{"Name": "TableName", "Value": table}, {"Name": "Operation", "Value": "BatchWriteItem"}]
    throttled_sum = _poll_until(
        lambda: _metric_stat_sum(ctx, "AWS/DynamoDB", "ThrottledRequests", dims),
        lambda v: v > 0,
        timeout_s=300,
        interval_s=2,
    )
    if not throttled_sum or throttled_sum <= 0:
        raise AssertionError(
            "ThrottledRequests datapoint for BatchWriteItem did not appear within a 5min poll window; "
            "CloudWatch metric ingestion for DynamoDB can take several minutes."
        )
    assert throttled_sum > 0, f"expected a positive ThrottledRequests sum, got {throttled_sum!r}"
    assert total_unprocessed > 0, f"expected a positive unprocessed-item count, got {total_unprocessed!r}"


# ===== helpers =====
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
    # A new role is not assumable at once: retry the InvalidParameterValueException it causes
    # every 2 s for up to 60 s, capped by the runner's remaining time.
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while True:
        try:
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
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
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
    )
    if wcu is None:
        kwargs["BillingMode"] = "PAY_PER_REQUEST"
    else:
        kwargs["ProvisionedThroughput"] = {"ReadCapacityUnits": rcu, "WriteCapacityUnits": wcu}
    kwargs["Tags"] = [{"Key": "sim2real", "Value": CHECK}]
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
