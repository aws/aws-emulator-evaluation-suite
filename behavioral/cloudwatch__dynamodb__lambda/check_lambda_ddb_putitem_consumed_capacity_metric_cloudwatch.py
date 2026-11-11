"""lambda-ddb-putitem-consumed-capacity-metric-cloudwatch."""
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

CHECK = "lambda-ddb-putitem-consumed-capacity-metric-cloudwatch"
GROUP = "sdk-invocation"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
import json, os, boto3

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    resp = ddb.put_item(
        TableName=table,
        Item={"pk": {"S": event["pk"]}, "val": {"S": "x"}},
        ReturnConsumedCapacity="TOTAL",
    )
    return {"ok": True, "capacity_units": resp["ConsumedCapacity"]["CapacityUnits"]}
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A Lambda-driven PutItem call's own reported ConsumedCapacity is reproduced exactly by
    ConsumedWriteCapacityUnits in CloudWatch -- the two accounting planes must agree, not merely
    both be positive."""
    table = _create_table(ctx)
    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "*"}],
    )
    fn = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table})

    api_wcu = 0.0
    for _ in range(3):
        resp = _invoke(ctx, fn, {"pk": f"item-{uuid.uuid4()}"})
        assert resp["ok"] is True, f"lambda-side put_item reported ok={resp.get('ok')!r}, expected True"
        api_wcu += resp["capacity_units"]

    total = _poll_until_equal(
        ctx,
        lambda: _metric_stat_sum(
            ctx, "AWS/DynamoDB", "ConsumedWriteCapacityUnits",
            [{"Name": "TableName", "Value": table}],
        ),
        api_wcu,
        timeout_s=240,
    )
    assert total == api_wcu, (
        f"CloudWatch reports ConsumedWriteCapacityUnits Sum={total!r} for table {table!r} while "
        f"the 3 Lambda-driven PutItems reported {api_wcu!r} write capacity units in their own "
        f"ConsumedCapacity responses; the metric plane must reproduce the API plane's own "
        f"accounting exactly, not merely be positive"
    )


# ===== helpers =====
_PREFIX = "sim2real-cwlambdadb-"
_LOGS_STMT = {
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "*",
}
_TAGS_KV = [{"Key": "sim2real", "Value": CHECK}]


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
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV)
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
    ddb.create_table(**kwargs, Tags=_TAGS_KV)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _poll_until_equal(ctx, probe, want, *, timeout_s: float, hold_s: float = 40.0):
    """Poll probe() every 2 s until it has equalled want for hold_s, so a sum still climbing past
    want is caught; at the deadline (capped by ctx.time_left()) return the last reading, or raise
    if it equals want but has not held."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))
    held_since = None
    while True:
        last = probe()
        now = time.monotonic()
        held_since = (held_since or now) if last == want else None
        if held_since is not None and now - held_since >= hold_s:
            return last
        if now >= deadline:
            if held_since is not None:
                raise AssertionError(
                    f"ConsumedWriteCapacityUnits reached {want!r} but did not hold it for {hold_s}s "
                    f"within {timeout_s}s"
                )
            return last
        time.sleep(2)


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
