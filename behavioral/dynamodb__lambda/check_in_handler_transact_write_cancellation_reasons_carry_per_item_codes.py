"""in-handler-transact-write-cancellation-reasons-carry-per-item-codes."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "in-handler-transact-write-cancellation-reasons-carry-per-item-codes"
GROUP = "sdk-in-handler"
SERVICES = ["dynamodb", "lambda"]

_CANCELLED = (
    "TransactionCanceledException",
    "Transaction cancelled, please refer cancellation reasons for specific reasons "
    "[None, ConditionalCheckFailed]",
)
_REASONS = [
    {"Code": "None"},
    {
        "Code": "ConditionalCheckFailed",
        "Message": "The conditional request failed",
        "Item": {"pk": {"S": "acct"}, "v": {"N": "1"}},
    },
]

_HANDLER = """\
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    ddb = boto3.client("dynamodb")
    table = event["table"]
    try:
        ddb.transact_write_items(TransactItems=[
            {"Put": {"TableName": table, "Item": {"pk": {"S": "fresh"}}}},
            {"Update": {
                "TableName": table,
                "Key": {"pk": {"S": "acct"}},
                "UpdateExpression": "SET v = :next",
                "ConditionExpression": "v = :expected",
                "ExpressionAttributeValues": {":expected": {"N": "2"}, ":next": {"N": "3"}},
                "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
            }},
        ])
    except ClientError as exc:
        return {
            "exception": type(exc).__name__,
            "error": [exc.response["Error"]["Code"], exc.response["Error"]["Message"]],
            "reasons": exc.response.get("CancellationReasons"),
        }
    return {"exception": None}
"""


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A handler's own boto3 sees a cancelled TransactWriteItems with per-item reasons.

    The modeled TransactionCanceledException carries AWS's message and CancellationReasons in item
    order: None, then ConditionalCheckFailed with the ALL_OLD item; neither write applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    table = ctx.unique_name("sim2real-behav-sdk-")
    ctx.on_cleanup(
        _teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException")
    )
    arn = ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TableDescription"]["TableArn"]
    attempts = max(1, int(_budget_s(ctx, 120.0) // 2))
    ddb.get_waiter("table_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": attempts}
    )
    ddb.put_item(TableName=table, Item={"pk": {"S": "acct"}, "v": {"N": "1"}})

    role = _role_arn(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:GetItem"],
                "Resource": arn,
            }
        ],
    )
    name = _function(ctx, lam, "python3.12", role, _make_zip(_HANDLER))
    # Retried while the new grant is not yet effective.
    error, got = _invoke_retrying(
        ctx,
        lam,
        name,
        {"table": table},
        lambda r: r[0] is None and (r[1].get("error") or [None])[0] == "AccessDeniedException",
    )
    assert error is None, f"the handler failed with FunctionError={error}: {json.dumps(got)[:500]}"

    assert got["exception"] == _CANCELLED[0], (
        f"the handler's client raised {got['exception']!r}, expected the modeled {_CANCELLED[0]}"
    )
    assert tuple(got["error"]) == _CANCELLED, (
        f"error was {got['error']!r}, expected {list(_CANCELLED)!r}"
    )
    assert got["reasons"] == _REASONS, (
        f"CancellationReasons in the handler were {got['reasons']!r}, expected {_REASONS!r}"
    )
    acct = ddb.get_item(TableName=table, Key={"pk": {"S": "acct"}}, ConsistentRead=True)
    assert acct.get("Item") == {"pk": {"S": "acct"}, "v": {"N": "1"}}, (
        f"the cancelled transaction changed the conditioned item: {acct.get('Item')!r}"
    )
    fresh = ddb.get_item(TableName=table, Key={"pk": {"S": "fresh"}}, ConsistentRead=True)
    assert "Item" not in fresh, f"the cancelled transaction wrote its Put: {fresh['Item']!r}"


# ===== helpers =====
def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _role_arn(ctx, statements=()) -> str:
    """An execution role allowed to write its logs plus ``statements``; deleted in cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            *statements,
        ],
    }
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"), "NoSuchEntity")
    )
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    return arn


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush and recreate the group after delete_function returns, so
    one delete is one round, not a teardown.
    """
    logs = ctx.client("logs")
    budget = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + budget
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget:.0f}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


def _function(ctx, lam, runtime, role, code) -> str:
    """Create a function, retried while its new role propagates, and wait until it is Active."""
    name = ctx.unique_name(f"sim2real-behav-{runtime.replace('.', '')}-")
    # LIFO: the log group is reaped after the function itself is deleted.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")
    )
    kwargs = dict(
        FunctionName=name,
        Runtime=runtime,
        Handler="index.handler",
        Role=role,
        Code={"ZipFile": code},
        MemorySize=128,
        Timeout=30,
        Architectures=["x86_64"],
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while creating {name}: {exc}") from exc
            raise
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {name} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return name
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"run budget ended before {name} was Active")
    raise AssertionError(f"{name} Active not met within the wait. Last: {last!r}")


def _invoke_retrying(ctx, lam, fn, payload, retry):
    """(FunctionError, payload) of a sync invoke, repeated while ``retry(result)`` within budget.

    A role's new inline grant can lag, so a denied first call is retried, never graded.
    """
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        resp = lam.invoke(
            FunctionName=fn,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode(),
        )
        assert resp["StatusCode"] == 200, (
            f"Function {fn}: synchronous Invoke StatusCode was {resp['StatusCode']!r}, expected 200"
        )
        result = (resp.get("FunctionError"), json.loads(resp["Payload"].read()))
        if not retry(result):
            return result
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {fn} still returned {result!r}")
            return result
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
