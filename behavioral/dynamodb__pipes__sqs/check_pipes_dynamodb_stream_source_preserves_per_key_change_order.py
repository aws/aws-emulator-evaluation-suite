"""pipes-dynamodb-stream-source-preserves-per-key-change-order."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-dynamodb-stream-source-preserves-per-key-change-order"

GROUP = "ordering"

SERVICES = ["dynamodb", "pipes", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Ten sequential writes to one DynamoDB partition key arrive at the pipe's FIFO target in write
    order with ten distinct eventIDs, every record naming that key and the source stream.
    """
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")
    n = 10
    pk = _xname(ctx, "key")
    warm_pk = _xname(ctx, "warm")

    table = _xname(ctx, "tbl")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(_tolerant(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    stream_arn = _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t.get("TableStatus") == "ACTIVE" and t.get("LatestStreamArn"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=1.0,
        description=f"table {table} ACTIVE with a stream",
    )["LatestStreamArn"]

    target = _create_queue(ctx, fifo=True)
    role = _create_role(
        ctx,
        "pipes.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:DescribeStream",
                        "dynamodb:GetRecords",
                        "dynamodb:GetShardIterator",
                        "dynamodb:ListStreams",
                    ],
                    "Resource": stream_arn,
                },
                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]},
            ],
        },
    )

    pipe = _create_pipe(
        ctx,
        source=stream_arn,
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={
            "DynamoDBStreamParameters": {"StartingPosition": "LATEST", "BatchSize": 1}
        },
        TargetParameters={
            "SqsQueueParameters": {
                # One FIFO group: SQS preserves whatever order Pipes hands it.
                "MessageGroupId": "sim2real-order",
                "MessageDeduplicationId": "$.eventID",
            }
        },
    )

    # --- Warm-up barrier: StartingPosition=LATEST may establish the iterator after an early write.
    warmed = False
    warm_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + warm_s
    while time.monotonic() < deadline and not warmed:
        ddb.put_item(TableName=table, Item={"pk": {"S": warm_pk}, "w": {"S": str(time.time())}})
        window = min(5.0, max(1.0, deadline - time.monotonic()))
        bodies = _drain(ctx, target["url"], window_s=window,
                        until=lambda seen: any(warm_pk in raw for raw in seen))
        warmed = any(warm_pk in raw for raw in bodies)
    if not warmed and _budget_spent(ctx):
        raise TimeoutError(f"a warm-up change record from table {table!r} reaching the FIFO target: "
                           "the run budget ended first; not graded")
    assert warmed, (
        f"no warm-up change record from table {table!r} reached the FIFO target within "
        f"{warm_s:.0f}s, so "
        f"pipe {pipe!r} never began consuming the stream"
    )

    # --- The graded sequence: n sequential writes to ONE partition key.
    for i in range(n):
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "i": {"N": str(i)}})

    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    distinct: set = set()
    while time.monotonic() < deadline and len(distinct) < n:
        window = min(3.0, max(1.0, deadline - time.monotonic()))
        for raw in _drain(ctx, target["url"], window_s=window):
            payload = json.loads(raw)
            for rec in payload if isinstance(payload, list) else [payload]:
                if rec.get("dynamodb", {}).get("Keys", {}).get("pk", {}).get("S") == pk:
                    collected.append(rec)
                    value = rec.get("dynamodb", {}).get("NewImage", {}).get("i", {}).get("N")
                    if value is not None:
                        distinct.add(value)

    if len(distinct) < n and _budget_spent(ctx):
        raise TimeoutError(f"the {n} changes to partition key {pk!r} reaching the FIFO target: "
                           "the run budget ended first; not graded")
    # A stream source is at-least-once: grade the ordered first arrivals, so only reordering fails.
    order = []
    for rec in collected:
        value = rec["dynamodb"]["NewImage"]["i"]["N"]
        if value not in order:
            order.append(value)
    assert order == [str(i) for i in range(n)], (
        f"the pipe must deliver the {n} changes to partition key {pk!r} in write order; first "
        f"arrivals were {order!r} (expected {[str(i) for i in range(n)]!r}) over "
        f"{len(collected)} delivered record(s) from pipe {pipe!r}"
    )
    assert len({rec["eventID"] for rec in collected}) == n, (
        f"the {n} writes must produce {n} distinct stream eventIDs; got "
        f"{sorted({rec['eventID'] for rec in collected})!r}"
    )
    assert all(
        rec["dynamodb"]["Keys"] == {"pk": {"S": pk}} for rec in collected
    ), (
        f"every collected record must name exactly the one partition key {pk!r}; got "
        f"{[rec['dynamodb']['Keys'] for rec in collected]!r}"
    )
    assert all(rec.get("eventSourceARN") == stream_arn for rec in collected), (
        f"every record must name the source stream {stream_arn!r}; got "
        f"{[rec.get('eventSourceARN') for rec in collected]!r}"
    )
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_pipe(ctx, pipe)
    _gone_role(ctx, role["name"], "/sim2real/")
    _gone_queue(ctx, target["name"], target["url"])
    _gone_table(ctx, table, {"pk": {"S": pk}})
    _gone_table_stream(ctx, table, stream_arn)

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, ctx, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
            AttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "raw": msg["Body"],
                    "attributes": msg.get("Attributes", {}),
                }
            )
            if delete:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(messages) < expected_count:
        raise AssertionError(
            f"expected {expected_count} message(s) on {queue_url}, got {len(messages)} within "
            f"{timeout_s}s: {messages!r}"
        )
    return messages


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _drain(ctx, queue_url, window_s=20.0, until=None):
    """Receive what shows up on a queue inside a bounded window, ending early once until(bodies)."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and not (until and until(seen)):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        )
        msgs = resp.get("Messages", [])
        for msg in msgs:
            seen.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    # IAM propagation exposes no condition to poll; _create_pipe's bounded retry is the wait.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _create_pipe_role(ctx, source_arn: str, target_arn, extra=None) -> dict[str, str]:
    """The standard pipe execution role: read the source queue, send to the target queue(s)."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(
        ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                 wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for. Returns the pipe name.

    Pipes assumes the role at create time; only the assume-role refusals are retried, bounded.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last_err = None
    for _ in range(20):
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState=desired_state,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "iam:PassRole" in msg:
                last_err = exc
                time.sleep(2)
                continue
            raise
    else:
        raise AssertionError(f"could not create pipe {name}: {last_err}")
    ctx.on_cleanup(_tolerant(lambda: ctx.client("pipes").delete_pipe(Name=name), "NotFoundException"))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 240.0),
        interval_s=1.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        assert msg == message, f"{what}: {code} message {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _gone_pipe(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    pipes.delete_pipe(Name=name)
    nf = ("NotFoundException",)
    missing = f"Pipe {name} does not exist."
    _poll_refused(lambda: pipes.describe_pipe(Name=name), nf, 404, f"DescribePipe {name}", missing)
    listed = {p["Name"] for p in _paged(pipes, "list_pipes", "Pipes", NamePrefix=name)}
    assert name not in listed, f"ListPipes still lists deleted pipe {name}"
    _refused(lambda: pipes.start_pipe(Name=name), nf, 404, f"StartPipe {name}", missing)


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    missing = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", missing)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", missing,
    )


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    missing = "The specified queue does not exist."
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", missing)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}", missing)


def _gone_table(ctx, name: str, item: dict) -> None:
    ddb = ctx.client("dynamodb")
    ddb.delete_table(TableName=name)
    nf = ("ResourceNotFoundException",)
    missing = f"Requested resource not found: Table: {name} not found"
    _poll_refused(lambda: ddb.describe_table(TableName=name), nf, 400, f"DescribeTable {name}", missing)
    assert name not in _paged(ddb, "list_tables", "TableNames"), f"ListTables still lists deleted table {name}"
    _refused(lambda: ddb.put_item(TableName=name, Item=item), nf, 400, f"PutItem {name}", "Requested resource not found")


_STREAM_NF = ("ResourceNotFoundException",)


def _gone_table_stream(ctx, table: str, stream_arn: str) -> None:
    """The deleted table's stream is a DISABLED tombstone with every shard closed, or not found.
    AWS keeps a DISABLED stream listed and readable for its retention window."""
    streams = ctx.client("dynamodbstreams")
    deadline = time.monotonic() + _GONE_S
    while True:
        try:
            desc = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
        except ClientError as exc:
            code, status, msg = _err(exc)
            assert code in _STREAM_NF and status == 400 and msg.strip(), (
                f"DescribeStream on the deleted table's stream: expected the DISABLED tombstone or "
                f"ResourceNotFoundException HTTP 400, got {code!r} HTTP {status!r}: {msg[:150]!r}"
            )
            break
        state = desc.get("StreamStatus")
        if state == "DISABLED":
            open_shards = [
                sh["ShardId"] for sh in desc.get("Shards", [])
                if not sh.get("SequenceNumberRange", {}).get("EndingSequenceNumber")
            ]
            assert not open_shards, f"DISABLED stream of deleted table still has open shards {open_shards}"
            break
        assert state == "DISABLING", f"stream of deleted table {table} is {state!r}, not DISABLED"
        assert time.monotonic() < deadline, f"stream of deleted table {table} still DISABLING"
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
