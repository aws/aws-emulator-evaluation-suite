"""durable-execution-step-retry-recovers-and-replay-skips-completed-steps."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-execution-step-retry-recovers-and-replay-skips-completed-steps"
GROUP = "state-machine"
SERVICES = ["dynamodb", "iam", "lambda", "logs", "sts"]

_HANDLER_CODE = '''
import time

import boto3

from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
    durable_step,
)
from aws_durable_execution_sdk_python.config import Duration, StepConfig
from aws_durable_execution_sdk_python.retries import RetryStrategyConfig, create_retry_strategy
from botocore.exceptions import ClientError

_dynamodb = boto3.client("dynamodb")

_STEP_B_CONFIG = StepConfig(
    retry_strategy=create_retry_strategy(
        RetryStrategyConfig(
            max_attempts=3,
            initial_delay=Duration.from_seconds(5),
            max_delay=Duration.from_seconds(5),
            backoff_rate=1.0,
        )
    )
)


_NOT_YET = {}


def _bump(table_name, step_id):
    # The role's dynamodb:UpdateItem grant can still be propagating when the first step
    # runs; retry only that exact refusal, against a deadline, rather than failing on it.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            resp = _dynamodb.update_item(
                TableName=table_name,
                Key={"StepId": {"S": step_id}},
                UpdateExpression="ADD RunCount :one",
                ExpressionAttributeValues={":one": {"N": "1"}},
                ReturnValues="UPDATED_NEW",
            )
            return int(resp["Attributes"]["RunCount"]["N"])
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"], err["Message"]) != _NOT_YET.get("pair") or time.monotonic() > deadline:
                raise
            time.sleep(2)


@durable_step
def step_a(step_context, table_name):
    _bump(table_name, "step_a")
    return {"step": "a", "value": "alpha"}


@durable_step
def step_b(step_context, table_name):
    attempt = _bump(table_name, "step_b")
    if attempt == 1:
        raise RuntimeError("transient failure on attempt 1")
    return {"step": "b", "value": "beta"}


@durable_step
def step_c(step_context, table_name):
    _bump(table_name, "step_c")
    return {"step": "c", "value": "gamma"}


@durable_execution
def lambda_handler(event, context: DurableContext):
    table_name = event["table_name"]
    _NOT_YET["pair"] = ("AccessDeniedException", event["update_denied_message"])
    ra = context.step(step_a(table_name))
    rb = context.step(step_b(table_name), config=_STEP_B_CONFIG)
    context.wait(Duration.from_seconds(2))
    rc = context.step(step_c(table_name))
    return {"results": [ra, rb, rc]}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A durable step that raises on its first attempt and succeeds on retry checkpoints
    StepFailed then StepSucceeded for that step, the execution's final Result carries every
    step's stored value, and the checkpoint replay after a wait never re-runs a completed step."""
    table_name = _create_counter_table(ctx)
    role_arn = _create_durable_role(ctx, table_name)
    fn_name = ctx.unique_name("sim2real-xsvc-derty-")
    _create_durable_function(
        ctx,
        name=fn_name,
        role_arn=role_arn,
        handler_source=_HANDLER_CODE,
        durable_config={"ExecutionTimeout": 300, "RetentionPeriodInDays": 1},
    )

    arn = _invoke_durable(
        ctx,
        function_name=fn_name,
        payload={
            "table_name": table_name,
            "update_denied_message": _update_denied_message(ctx, role_arn, fn_name, table_name),
        },
        execution_name=ctx.unique_name("sim2real-xsvc-derty-run-"),
    )

    final = _poll_until(
        ctx,
        lambda: _get_execution(ctx, arn),
        lambda e: e["Status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert final["Status"] == "SUCCEEDED", f"expected SUCCEEDED, got {final['Status']}: {final.get('Error')}"

    result = json.loads(final["Result"])
    assert result == {
        "results": [
            {"step": "a", "value": "alpha"},
            {"step": "b", "value": "beta"},
            {"step": "c", "value": "gamma"},
        ]
    }, f"final Result should carry every step's stored value exactly, got {result!r}"

    events = _get_history_events(ctx, arn)
    step_b_events = [e for e in events if e.get("Name") == "step_b"]
    failed = [e for e in step_b_events if e.get("StepFailedDetails") is not None]
    succeeded = [e for e in step_b_events if e.get("StepSucceededDetails") is not None]
    assert len(failed) == 1, f"expected exactly one StepFailed checkpoint for step_b, got {len(failed)}: {step_b_events!r}"
    assert len(succeeded) == 1, (
        f"expected exactly one StepSucceeded checkpoint for step_b, got {len(succeeded)}: {step_b_events!r}"
    )
    assert failed[0]["EventId"] < succeeded[0]["EventId"], (
        "step_b's StepFailed checkpoint should precede its StepSucceeded checkpoint, got "
        f"EventIds {failed[0]['EventId']} then {succeeded[0]['EventId']}"
    )
    failed_retry = failed[0]["StepFailedDetails"]["RetryDetails"]
    succeeded_retry = succeeded[0]["StepSucceededDetails"]["RetryDetails"]
    assert failed_retry["CurrentAttempt"] == 1, (
        f"step_b's failed checkpoint should report CurrentAttempt 1, got {failed_retry!r}"
    )
    assert succeeded_retry["CurrentAttempt"] == 2, (
        f"step_b's succeeded checkpoint should report CurrentAttempt 2, got {succeeded_retry!r}"
    )

    # A completed step's result is substituted from the checkpoint log on resume, never
    # re-executed: the side-effect counter for every step stayed at exactly one run each,
    # even though the execution crossed a wait-induced suspend/resume boundary after step_b.
    counts = _read_counts(ctx, table_name)
    assert counts == {"step_a": 1, "step_b": 2, "step_c": 1}, (
        f"expected step_a and step_c to run exactly once and step_b exactly twice "
        f"(its one failed attempt plus its one successful retry), got {counts!r}"
    )


# ===== helpers (self-contained) =====


_ROLE_NOT_YET = ("InvalidParameterValueException", "The role defined for the function cannot be assumed by Lambda.")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _update_denied_message(ctx: Any, role_arn: str, fn_name: str, table_name: str) -> str:
    """The exact refusal the function's own UpdateItem gets while its role's grant propagates."""
    account = role_arn.split(":")[4]
    role_name = role_arn.rsplit("/", 1)[1]
    table_arn = f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table_name}"
    return (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{fn_name} is not authorized to "
        f"perform: dynamodb:UpdateItem on resource: {table_arn} because no identity-based policy "
        "allows the dynamodb:UpdateItem action"
    )


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _poll_until(ctx: Any, probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"the run budget ended first; not graded; last={last!r}")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_counter_table(ctx: Any) -> str:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-xsvc-derty-counts-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "StepId", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "StepId", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _poll_until(
        ctx,
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return table_name


def _read_counts(ctx: Any, table_name: str) -> dict:
    ddb = ctx.client("dynamodb")
    counts = {}
    for step_id in ("step_a", "step_b", "step_c"):
        item = ddb.get_item(
            TableName=table_name, Key={"StepId": {"S": step_id}}, ConsistentRead=True
        ).get("Item")
        counts[step_id] = int(item["RunCount"]["N"]) if item else 0
    return counts


_DURABLE_MANAGED_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)


def _create_durable_role(ctx: Any, table_name: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    role_name = ctx.unique_name("sim2real-xsvc-derty-role-")

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="durable-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for policy_arn in _DURABLE_MANAGED_POLICIES:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(_cleanup)
    role_arn = resp["Role"]["Arn"]

    for policy_arn in _DURABLE_MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    account = sts.get_caller_identity()["Account"]
    table_arn = f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table_name}"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "dynamodb:UpdateItem", "Resource": table_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="durable-inline", PolicyDocument=json.dumps(policy_doc))

    return role_arn


def _create_durable_function(
    ctx: Any,
    *,
    name: str,
    role_arn: str,
    handler_source: str,
    durable_config: dict,
    timeout_s: float = 120.0,
) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _zip_from_source("lambda_function.py", handler_source)
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=120,
                MemorySize=256,
                DurableConfig=durable_config,
                Tags={"sim2real": "true"},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"], err["Message"]) != _ROLE_NOT_YET or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    if cfg["State"] != "Active":
        raise AssertionError(f"durable function failed to activate: {cfg.get('StateReason')}")
    return resp["FunctionArn"]


def _invoke_durable(ctx: Any, *, function_name: str, payload: dict, execution_name: str) -> str:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
        DurableExecutionName=execution_name,
    )
    assert resp["StatusCode"] == 202, f"expected async invoke StatusCode 202, got {resp['StatusCode']}"
    arn = resp.get("DurableExecutionArn")
    if arn:
        return arn
    return _poll_until(
        ctx,
        lambda: _find_execution_arn(lam, function_name, execution_name),
        lambda a: a is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )


def _get_execution(ctx: Any, arn: str) -> dict:
    # GetDurableExecution can lag the async invoke's own acceptance by a beat even after the
    # execution is already visible via ListDurableExecutionsByFunction.
    try:
        return ctx.client("lambda").get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return {"Status": "PENDING"}
        raise


def _find_execution_arn(lam, function_name: str, execution_name: str):
    execs = lam.list_durable_executions_by_function(FunctionName=function_name)["DurableExecutions"]
    for e in execs:
        if e["DurableExecutionName"] == execution_name:
            return e["DurableExecutionArn"]
    return None


def _get_history_events(ctx: Any, arn: str) -> list:
    lam = ctx.client("lambda")
    events: list = []
    marker = None
    while True:
        kwargs = {"DurableExecutionArn": arn, "MaxItems": 1000, "IncludeExecutionData": True}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.get_durable_execution_history(**kwargs)
        events.extend(resp.get("Events", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
    return events


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log line can flush and recreate the group after a single delete, so one
    delete is not a teardown: raises if it is still coming back when ``budget_s`` runs out.
    """
    deadline = time.monotonic() + budget_s
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
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
