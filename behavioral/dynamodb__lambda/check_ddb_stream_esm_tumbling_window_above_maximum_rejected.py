"""ddb-stream-esm-tumbling-window-above-maximum-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-stream-esm-tumbling-window-above-maximum-rejected"
GROUP = "event-source-mapping"
SERVICES = ["dynamodb", "lambda"]

_MAX_WINDOW_S = 900


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping rejects a DynamoDB-stream TumblingWindowInSeconds above its
    documented 900 s maximum with ValidationException, carrying the value in the message; the
    same stream mapped at the maximum succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/API_CreateEventSourceMapping.html
    """
    table_name, stream_arn = _stream_table(ctx)
    role_arn = _create_role(ctx, stream_arn)
    fn_arn = _create_function(ctx, role_arn)
    over = _MAX_WINDOW_S + 1

    code, message = _error(lambda: ctx.client("lambda").create_event_source_mapping(
        EventSourceArn=stream_arn, FunctionName=fn_arn, StartingPosition="TRIM_HORIZON",
        BatchSize=10, TumblingWindowInSeconds=over,
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '{over}' at 'tumblingWindowInSeconds' failed to "
        f"satisfy constraint: Member must have value less than or equal to {_MAX_WINDOW_S}"
    ), f"unexpected message: {message!r}"
    leftover = ctx.client("lambda").list_event_source_mappings(FunctionName=fn_arn)["EventSourceMappings"]
    assert leftover == [], f"the refused CreateEventSourceMapping left a mapping behind: {leftover!r}"

    uuid_ = _create_esm(ctx, stream_arn, fn_arn, StartingPosition="TRIM_HORIZON", BatchSize=10,
                        TumblingWindowInSeconds=_MAX_WINDOW_S)
    mapping = ctx.client("lambda").get_event_source_mapping(UUID=uuid_)
    assert mapping["State"] == "Enabled", f"control mapping did not reach Enabled: {mapping!r}"
    assert mapping["TumblingWindowInSeconds"] == _MAX_WINDOW_S, (
        f"control mapping must echo the max window {_MAX_WINDOW_S}, got "
        f"{mapping['TumblingWindowInSeconds']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; raises AssertionError on unexpected success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError("expected a ClientError, the call unexpectedly succeeded")


def _stream_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    desc = _poll(
        ctx, lambda: ddb.describe_table(TableName=name)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE" and t.get("LatestStreamArn"),
        timeout_s=60, interval_s=2.0, description=f"table {name} ACTIVE with a stream",
    )
    return name, desc["LatestStreamArn"]


def _create_role(ctx, stream_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    statements = [
        {"Effect": "Allow",
         "Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream"],
         "Resource": f"{stream_arn}*"},
        {"Effect": "Allow", "Action": "dynamodb:ListStreams", "Resource": "*"},
    ]
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
                             "NoSuchEntity"))
    return role["Arn"]


def _create_function(ctx, role_arn: str) -> str:
    import io
    import zipfile

    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {'state': {}}\n")
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
    kwargs: dict[str, Any] = dict(
        FunctionName=name, Runtime="python3.13", Handler="index.handler", Role=role_arn,
        Code={"ZipFile": buf.getvalue()}, Timeout=30, MemorySize=128, Publish=True,
        Tags={"sim2real": CHECK},
    )

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in err["Message"]:
                return None
            raise

    resp = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=3,
                description="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name).get("State"),
         lambda s: s == "Active", timeout_s=90, interval_s=3,
         description=f"function {name} Active")
    return resp["FunctionArn"]


def _create_esm(ctx, source_arn: str, function_arn: str, **kwargs) -> str:
    lam = ctx.client("lambda")
    params = dict(EventSourceArn=source_arn, FunctionName=function_arn, Enabled=True, **kwargs)
    uuid_ = lam.create_event_source_mapping(**params)["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid_),
                             "ResourceNotFoundException"))
    _poll(ctx, lambda: lam.get_event_source_mapping(UUID=uuid_)["State"], lambda s: s == "Enabled",
         timeout_s=90, interval_s=3, description=f"ESM {uuid_} Enabled")
    return uuid_


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result) holds; raise TimeoutError at the capped deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s; last saw {last!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
