"""lambda-ddb-table-not-exist-error-logged-cloudwatch."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-ddb-table-not-exist-error-logged-cloudwatch"
GROUP = "arn-resolution"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
import logging, boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    table = event["table"]
    ddb = boto3.client("dynamodb")
    try:
        resp = ddb.get_item(TableName=table, Key={"pk": {"S": "x"}})
        logger.info("GET_OK found=%s", "Item" in resp)
        return {"ok": True}
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        logger.info("GET_ERROR code=%s table=%s", code, table)
        return {"ok": False, "code": code, "message": exc.response["Error"].get("Message")}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A GetItem from a Lambda handler on a table that does not exist fails with ResourceNotFoundException
    and the exact message 'Requested resource not found', which is logged in CloudWatch Logs; the same
    call on an existing table succeeds and is logged as such."""
    role_arn = _create_role(
        ctx, [{"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": "*"}]
    )
    fn = _create_function(ctx, role_arn, _HANDLER_SRC)

    missing_table = ctx.unique_name("sim2real-cwlambdadb-missing-tbl-")
    resp = _invoke(ctx, fn, {"table": missing_table})
    assert resp["ok"] is False
    assert resp["code"] == "ResourceNotFoundException"
    assert resp.get("message") == "Requested resource not found", resp

    log_text = _poll_until(
        lambda: _log_tail(ctx, fn),
        lambda text: "GET_ERROR" in text,
        timeout_s=90,
        interval_s=2,
        description="GET_ERROR log line for missing table",
    )
    assert f"GET_ERROR code=ResourceNotFoundException table={missing_table}" in log_text

    # Positive control: a real table exists and the same handler succeeds against it.
    real_table = _create_table(ctx)
    ctx.client("dynamodb").put_item(TableName=real_table, Item={"pk": {"S": "x"}, "val": {"S": "y"}})
    ok_resp = _invoke(ctx, fn, {"table": real_table})
    assert ok_resp["ok"] is True

    ok_log = _poll_until(
        lambda: _log_tail(ctx, fn),
        lambda text: "GET_OK found=True" in text,
        timeout_s=90,
        interval_s=2,
        description="GET_OK log line for the positive-control table",
    )
    assert "GET_OK found=True" in ok_log


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


def _create_table(ctx: Any) -> str:
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, "tbl")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
