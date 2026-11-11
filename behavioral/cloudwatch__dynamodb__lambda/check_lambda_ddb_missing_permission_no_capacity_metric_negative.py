"""lambda-ddb-missing-permission-no-capacity-metric-negative."""
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

CHECK = "lambda-ddb-missing-permission-no-capacity-metric-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
import os, boto3
from botocore.exceptions import ClientError

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    try:
        ddb.put_item(TableName=table, Item={"pk": {"S": event["pk"]}, "val": {"S": "x"}})
        return {"ok": True}
    except ClientError as exc:
        err = exc.response["Error"]
        return {"ok": False, "code": err["Code"], "message": err.get("Message")}
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html
@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A Lambda role without dynamodb:PutItem gets AccessDeniedException, writes no item and
    registers no ConsumedWriteCapacityUnits, while a permitted role's write in the same window is
    metered."""
    denied_table = _create_table(ctx)
    allowed_table = _create_table(ctx)
    ddb = ctx.client("dynamodb")

    # Negative: role with only logging permission, no dynamodb access at all.
    denied_role = _create_role(ctx, [])
    denied_fn = _create_function(ctx, denied_role, _HANDLER_SRC, env={"TABLE_NAME": denied_table})

    # Positive control: role with the permission, writing to a SEPARATE table so its consumed
    # capacity can never be mistaken for the denied request's.
    allowed_role = _create_role(
        ctx, [{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "*"}]
    )
    allowed_fn = _create_function(ctx, allowed_role, _HANDLER_SRC, env={"TABLE_NAME": allowed_table})

    denied_pk = f"denied-{uuid.uuid4()}"
    allowed_pk = f"allowed-{uuid.uuid4()}"

    # Fire both at the same moment: the denied write and its positive-control twin.
    denied_resp = _invoke(ctx, denied_fn, {"pk": denied_pk})
    allowed_resp = _invoke(ctx, allowed_fn, {"pk": allowed_pk})

    assert denied_resp["ok"] is False, f"expected the denied write to fail, got {denied_resp}"
    assert denied_resp["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {denied_resp['code']}"
    )
    assert denied_resp.get("message") == _put_denied_message(ctx, denied_role, denied_fn, denied_table), (
        f"unexpected AccessDeniedException message: {denied_resp.get('message')!r}"
    )
    assert allowed_resp["ok"] is True, f"expected the positive control to succeed, got {allowed_resp}"

    got_denied = ddb.get_item(TableName=denied_table, Key={"pk": {"S": denied_pk}})
    assert "Item" not in got_denied, "item must not have been written when the write was denied"
    got_allowed = ddb.get_item(TableName=allowed_table, Key={"pk": {"S": allowed_pk}})
    assert "Item" in got_allowed, "positive control's item must have been written"

    # Poll both tables' metrics together and stop the instant the positive control's own write
    # registers -- that is the demonstrated latency bound. A window shorter than this would prove
    # nothing, since a target that silently drops the metric would look identical to one that
    # simply hasn't ingested it yet.
    def _probe() -> tuple[float, float]:
        return (
            _metric_stat_sum(
                ctx, "AWS/DynamoDB", "ConsumedWriteCapacityUnits", [{"Name": "TableName", "Value": allowed_table}]
            ),
            _metric_stat_sum(
                ctx, "AWS/DynamoDB", "ConsumedWriteCapacityUnits", [{"Name": "TableName", "Value": denied_table}]
            ),
        )

    allowed_sum, denied_sum = _poll_until(
        _probe,
        lambda pair: pair[0] > 0,
        timeout_s=200,
        interval_s=10,
    )
    assert denied_sum == 0, (
        f"AccessDenied write must not register any consumed write capacity, got {denied_sum} "
        f"measured at the same instant the positive control's write first registered {allowed_sum} "
        "on its own table"
    )


_PREFIX = "sim2real-cwlambdadb-"
_LOGS_STMT = {
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "*",
}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _put_denied_message(ctx: Any, role_arn: str, function_name: str, table: str) -> str:
    """DynamoDB's refusal of a PutItem the function's role has no identity-based grant for."""
    _, partition, _, _, account, resource = role_arn.split(":", 5)
    role_name = resource.rsplit("/", 1)[-1]
    return (
        f"User: arn:{partition}:sts::{account}:assumed-role/{role_name}/{function_name} is not "
        f"authorized to perform: dynamodb:PutItem on resource: "
        f"arn:{partition}:dynamodb:{ctx.region}:{account}:table/{table} because no identity-based "
        f"policy allows the dynamodb:PutItem action"
    )


def _create_role(ctx: Any, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
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
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"poll timed out after {timeout_s}s; last value was {last!r}")
        time.sleep(interval_s)


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
