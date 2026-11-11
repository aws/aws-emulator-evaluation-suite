"""events-pipes-enrichment-dynamodb-stream-filter-drops-modify-and-remove-before-enrichment."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pipes-enrichment-dynamodb-stream-filter-drops-modify-and-remove-before-enrichment"
GROUP = "filtering"
SERVICES = ["dynamodb", "lambda", "pipes", "sqs"]

_ENRICH_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")

def handler(event, context):
    out = []
    for r in event:
        d = r["dynamodb"]
        img = d.get("NewImage", {})
        seen = {"eventName": r["eventName"], "pk": d["Keys"]["pk"]["S"],
                "v": img.get("v", {}).get("N")}
        _sqs.send_message(QueueUrl=os.environ["AUDIT_URL"], MessageBody=json.dumps(seen))
        out.append(dict(seen, enriched=True))
    return out
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB-stream pipe filtering eventName INSERT drops MODIFY and REMOVE before enrichment:
    for one key written INSERT(v1) -> MODIFY -> REMOVE -> INSERT(v3), the enrichment and the target
    see exactly the two INSERTs.
    """
    ddb = ctx.client("dynamodb")
    target = _create_queue(ctx)
    audit = _create_queue(ctx)
    table, stream_arn = _create_stream_table(ctx)
    enrichment = _create_enrichment(ctx, _ENRICH_CODE, env={"AUDIT_URL": audit["url"]},
                                    send_to=[audit["arn"]])
    role = _create_role(ctx, "pipes.amazonaws.com", _stream_pipe_statements(
        stream_arn, target["arn"], enrichment["arn"]))
    _create_pipe(ctx, source=stream_arn, target=target["arn"], role_arn=role["arn"],
                 Enrichment=enrichment["arn"],
                 SourceParameters={
                     "DynamoDBStreamParameters": {"StartingPosition": "LATEST", "BatchSize": 1},
                     "FilterCriteria": {"Filters": [{"Pattern": json.dumps(
                         {"eventName": ["INSERT"]})}]},
                 })
    _warm_up(ctx, table, target["url"])

    pk = _xname(ctx, "item")
    key = {"pk": {"S": pk}}
    ddb.put_item(TableName=table, Item={**key, "v": {"N": "1"}})
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                    ExpressionAttributeValues={":v": {"N": "2"}})
    ddb.delete_item(TableName=table, Key=key)
    ddb.put_item(TableName=table, Item={**key, "v": {"N": "3"}})

    # Barrier + positive control: Streams orders one key's changes and the pipe reads a shard in
    # order, so INSERT(v3) arriving proves the MODIFY and REMOVE were already dispositioned.
    # Stream sources are at-least-once, so records are matched by content.
    got = _drain_until(ctx, target["url"], lambda bodies: any(
        isinstance(b, dict) and b.get("pk") == pk and b.get("v") == "3" for b in bodies),
        timeout_s=150, description=f"INSERT(v3) of {pk!r} at the target")
    got += _drain_idle(ctx, target["url"])
    mine = [b for b in got if isinstance(b, dict) and b.get("pk") == pk]
    assert {(b["eventName"], b["v"]) for b in mine} == {("INSERT", "1"), ("INSERT", "3")}, (
        f"target should hold exactly INSERT v1 and v3 for {pk!r}: {mine!r}"
    )
    assert all(b.get("enriched") is True for b in mine), f"delivered records not enriched: {mine!r}"

    audited = [b for b in _drain_idle(ctx, audit["url"]) if isinstance(b, dict) and b.get("pk") == pk]
    names = sorted({b["eventName"] for b in audited})
    assert names == ["INSERT"], (
        f"the enrichment was handed records the filter should have dropped first: {audited!r}"
    )


def _drain_idle(ctx: Any, url: str) -> list[Any]:
    """Receive-and-delete until two consecutive long polls come back empty."""
    sqs = ctx.client("sqs")
    got: list[Any] = []
    empty = 0
    while empty < 2:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5).get("Messages", [])
        empty = 0 if msgs else empty + 1
        for m in msgs:
            got.append(_parse(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


def _create_stream_table(ctx: Any) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    table = _xname(ctx, "tbl")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    desc = _poll_until(lambda: ddb.describe_table(TableName=table)["Table"],
                       lambda t: t.get("TableStatus") == "ACTIVE" and t.get("LatestStreamArn"),
                       timeout_s=120, description=f"table {table} ACTIVE with a stream")
    return table, desc["LatestStreamArn"]


def _stream_pipe_statements(stream_arn: str, target_arn: str, function_arn: str) -> list[dict]:
    return [
        {"Effect": "Allow",
         "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords",
                    "dynamodb:GetShardIterator", "dynamodb:ListStreams"],
         "Resource": stream_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        {"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": function_arn},
    ]


def _warm_up(ctx: Any, table: str, target_url: str) -> None:
    """Write fresh warm-up INSERTs until one is seen at the target, so the LATEST iterator is known
    to be positioned before the measured writes. Warm-up deliveries are consumed here."""
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        warm = _xname(ctx, "warm")
        ddb.put_item(TableName=table, Item={"pk": {"S": warm}})
        until = time.monotonic() + 15
        while time.monotonic() < until:
            for m in sqs.receive_message(QueueUrl=target_url, MaxNumberOfMessages=10,
                                         WaitTimeSeconds=5).get("Messages", []):
                sqs.delete_message(QueueUrl=target_url, ReceiptHandle=m["ReceiptHandle"])
                if "warm" in m["Body"]:
                    return
    raise AssertionError(f"no warm-up change record from {table!r} reached the target within 150s")


_PREFIX = "sim2real-xsvc-"
_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0,
                description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last observed {last!r}")


def _create_queue(ctx: Any, **attrs: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), Attributes=dict(attrs),
                           tags=dict(_RES_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_role(ctx: Any, service: str, statements: list[dict]) -> dict[str, str]:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Path="/sim2real/",
                          Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
    return {"name": name, "arn": arn}


def _delete_role(ctx: Any, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise RuntimeError(f"iam role {name}: {exc}") from exc


def _reap_log_group(ctx: Any, fn_name: str) -> None:
    """A buffered log stream can recreate /aws/lambda/<fn> after a delete, so reap in a loop and
    declare a leak rather than hang. Registered before create_function so LIFO runs it last."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group}: {exc}") from exc
        deadline = time.monotonic() + 8
        reappeared = False
        while time.monotonic() < deadline:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if any(g["logGroupName"] == group for g in found):
                reappeared = True
                break
            time.sleep(2)
        if not reappeared:
            return
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_enrichment(ctx: Any, code: str, env: dict[str, str] | None = None,
                       send_to: list[str] | None = None) -> dict[str, str]:
    """A python Lambda used as the pipe's enrichment. Its role has NO logs permissions, so it
    cannot create a log group; the reap loop is still registered as a net."""
    statements = []
    if send_to:
        statements.append({"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": send_to})
    role = _create_role(ctx, "lambda.amazonaws.com", statements)
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    kwargs: dict[str, Any] = {
        "FunctionName": name, "Runtime": "python3.12", "Role": role["arn"],
        "Handler": "index.handler", "Code": {"ZipFile": buf.getvalue()},
        "Timeout": 30, "MemorySize": 128, "Tags": dict(_RES_TAGS),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            # A just-created execution role is not yet assumable by Lambda (IAM propagation).
            if (exc.response["Error"]["Code"] == "InvalidParameterValueException"
                    and time.monotonic() < deadline):
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name).get("State"),
                lambda s: s == "Active", timeout_s=90, description=f"lambda {name} Active")
    return {"name": name, "arn": arn}


def _create_pipe_role(ctx: Any, *, source_arn: str, target_arns: list[str],
                      function_arns: list[str]) -> dict[str, str]:
    return _create_role(ctx, "pipes.amazonaws.com", [
        {"Effect": "Allow",
         "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
         "Resource": source_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
        {"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": function_arns},
    ])


def _delete_pipe(ctx: Any, name: str) -> None:
    pipes = ctx.client("pipes")
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise RuntimeError(f"pipe {name} still present 120s after DeletePipe")


def _create_pipe(ctx: Any, *, source: str, target: str, role_arn: str,
                 desired_state: str = "RUNNING", **extra: Any) -> str:
    """CreatePipe, retrying only through the pipes-role propagation window, then wait for the
    pipe to settle in `desired_state`. Teardown waits for the pipe to be gone."""
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    deadline = time.monotonic() + 60
    while True:
        try:
            pipes.create_pipe(Name=name, RoleArn=role_arn, Source=source, Target=target,
                              DesiredState=desired_state,
                              Tags=dict(_RES_TAGS), **extra)
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] == "ValidationException"
                    and "role" in str(exc).lower() and time.monotonic() < deadline):
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    state = _poll_until(lambda: pipes.describe_pipe(Name=name), lambda d: d.get("CurrentState") in (
        desired_state, "CREATE_FAILED", "START_FAILED"), timeout_s=180, interval_s=4,
        description=f"pipe {name} {desired_state}")
    assert state["CurrentState"] == desired_state, (
        f"pipe {name} settled in {state['CurrentState']!r} ({state.get('StateReason')!r}), "
        f"expected {desired_state!r}"
    )
    return name


def _parse(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return body


def _drain_until(ctx: Any, url: str, done, *, timeout_s: float, description: str) -> list[Any]:
    """Receive-and-delete from `url` until done(bodies_so_far) is true; return every body read."""
    sqs = ctx.client("sqs")
    got: list[Any] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            got.append(_parse(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if done(got):
            return got
    raise AssertionError(f"{description} did not arrive within {timeout_s}s; read {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
