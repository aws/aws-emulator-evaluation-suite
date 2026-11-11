"""lambda-ddb-accessdenied-logged-to-cloudwatch-negative."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-ddb-accessdenied-logged-to-cloudwatch-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
import os, logging, boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    pk = event["pk"]
    try:
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "val": {"S": "x"}})
        logger.info("PUT_OK pk=%s", pk)
        return {"ok": True}
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        logger.info("PUT_DENIED code=%s pk=%s", code, pk)
        return {"ok": False, "code": code, "message": exc.response["Error"].get("Message")}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A PutItem the function's role is not granted fails inside the handler with AccessDeniedException
    and its exact message, writes no item and is logged in CloudWatch Logs, while an authorized twin
    logs success and writes the item."""
    table = _create_table(ctx)
    ddb = ctx.client("dynamodb")

    denied_role = _create_role(ctx, [])
    denied_fn = _create_function(ctx, denied_role, _HANDLER_SRC, env={"TABLE_NAME": table})
    allowed_role = _create_role(
        ctx, [{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "*"}]
    )
    allowed_fn = _create_function(ctx, allowed_role, _HANDLER_SRC, env={"TABLE_NAME": table})

    denied_pk = f"denied-{uuid.uuid4()}"
    denied_resp = _invoke(ctx, denied_fn, {"pk": denied_pk})
    assert denied_resp["ok"] is False, f"expected denied invocation to report ok=False, got {denied_resp!r}"
    assert denied_resp["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got code={denied_resp.get('code')!r}"
    )
    assert denied_resp.get("message") == _put_denied_message(ctx, denied_role, denied_fn, table), (
        f"unexpected AccessDeniedException message: {denied_resp.get('message')!r}"
    )
    denied_read = ddb.get_item(TableName=table, Key={"pk": {"S": denied_pk}})
    assert "Item" not in denied_read, f"expected no item written for denied pk={denied_pk!r}, got {denied_read!r}"

    denied_log = _poll_until(
        lambda: _log_tail(ctx, denied_fn),
        lambda text: "PUT_DENIED" in text,
        timeout_s=90,
        interval_s=2,
        description=f"PUT_DENIED entry in {denied_fn} logs",
    )
    assert "PUT_DENIED code=AccessDeniedException" in denied_log, (
        f"expected 'PUT_DENIED code=AccessDeniedException' in denied fn log, got tail: {denied_log[-200:]!r}"
    )

    allowed_pk = f"allowed-{uuid.uuid4()}"
    allowed_resp = _invoke(ctx, allowed_fn, {"pk": allowed_pk})
    assert allowed_resp["ok"] is True, f"expected allowed invocation to succeed, got {allowed_resp!r}"
    allowed_read = ddb.get_item(TableName=table, Key={"pk": {"S": allowed_pk}})
    assert "Item" in allowed_read, f"expected item written for allowed pk={allowed_pk!r}, got {allowed_read!r}"

    allowed_log = _poll_until(
        lambda: _log_tail(ctx, allowed_fn),
        lambda text: "PUT_OK" in text,
        timeout_s=90,
        interval_s=2,
        description=f"PUT_OK entry in {allowed_fn} logs",
    )
    assert f"PUT_OK pk={allowed_pk}" in allowed_log, (
        f"expected 'PUT_OK pk={allowed_pk}' in allowed fn log, got tail: {allowed_log[-200:]!r}"
    )


# ===== helpers =====
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
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
    # function deletion, so it leaks unless deleted separately (best-effort: never created if the
    # function is never successfully invoked).
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"))
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    if wcu is None:
        kwargs["BillingMode"] = "PAY_PER_REQUEST"
    else:
        kwargs["ProvisionedThroughput"] = {"ReadCapacityUnits": rcu, "WriteCapacityUnits": wcu}
    ddb.create_table(**kwargs)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not satisfied within {timeout_s}s, last value={last!r}")


def _log_tail(ctx: Any, function_name: str) -> str:
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    try:
        streams = logs.describe_log_streams(
            logGroupName=group, orderBy="LastEventTime", descending=True, limit=5
        )["logStreams"]
    except logs.exceptions.ResourceNotFoundException:
        return ""
    lines: list[str] = []
    for s in streams:
        events = logs.get_log_events(logGroupName=group, logStreamName=s["logStreamName"], limit=200)
        lines.extend(e["message"] for e in events.get("events", []))
    return "\n".join(lines)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
