"""xsvc-lambda-2-ddb-stream-esm-on-failure-sqs-receives-batch-info-pointer."""
from __future__ import annotations

import json
import textwrap
import time
import uuid
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-lambda-2-ddb-stream-esm-on-failure-sqs-receives-batch-info-pointer"
GROUP = "error-propagation"
SERVICES = ["dynamodb", "kinesis", "lambda"]

_ITEM = "ordered-item"
_VERSIONS = [0, 1, 2]             # three mutations of ONE item: one partition, one ordered batch
_POISON = 1
_MAX_RETRIES = 1
_MAX_RECORD_AGE_S = 3600
_EFFECT_BUDGET_S = 200


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB-streams ESM out of retries sends SQS a DDBStreamBatchInfo pointer, not the records.

    The pointer's shard, sequence range and batch size match the poisoned batch the function saw
    and resolve through GetShardIterator(AT_SEQUENCE_NUMBER) to exactly those records.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")
    marker = f"rawdata-{uuid.uuid4().hex}"
    sink = _create_table(ctx, "audit")
    ddb.put_item(TableName=sink["name"], Item={"pk": {"S": "log"}, "entries": {"L": []}})
    queue = _create_queue(ctx)
    source = _create_stream_table(ctx)

    code = """
    import json, os
    import boto3
    ddb = boto3.client("dynamodb")
    SINK_TABLE = os.environ["SINK_TABLE"]
    POISON = int(os.environ["POISON"])

    def handler(event, context):
        recs = event["Records"]
        vs = [int(r["dynamodb"]["NewImage"]["v"]["N"]) for r in recs]
        seqs = [r["dynamodb"]["SequenceNumber"] for r in recs]
        poisoned = POISON in vs
        entry = {"b": vs, "seqs": seqs, "ok": 0 if poisoned else 1}
        ddb.update_item(
            TableName=SINK_TABLE,
            Key={"pk": {"S": "log"}},
            UpdateExpression="SET #e = list_append(#e, :v)",
            ExpressionAttributeNames={"#e": "entries"},
            ExpressionAttributeValues={":v": {"L": [{"S": json.dumps(entry)}]}},
        )
        if poisoned:
            raise RuntimeError(f"poison version {POISON} in batch {vs}")
        return {"processed": len(vs)}
    """
    fn = _create_lambda(
        ctx, code,
        statements=[
            {"Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream",
                        "dynamodb:ListStreams"],
             "Resource": f"{source['arn']}/stream/*"},
            {"Action": ["dynamodb:UpdateItem"], "Resource": sink["arn"]},
            {"Action": ["sqs:SendMessage"], "Resource": queue["arn"]},
        ],
        env={"SINK_TABLE": sink["name"], "POISON": str(_POISON)},
    )

    # Committed before the ESM exists, and all to ONE item: distinct keys can land in distinct
    # batches, while one item's mutations are one ordered sequence a TRIM_HORIZON poll hands over.
    for v in _VERSIONS:
        ddb.put_item(TableName=source["name"],
                     Item={"pk": {"S": _ITEM}, "v": {"N": str(v)}, "m": {"S": marker}})
    _create_esm(ctx, fn["name"], source["stream_arn"],
                StartingPosition="TRIM_HORIZON",
                BatchSize=10,
                MaximumBatchingWindowInSeconds=0,
                BisectBatchOnFunctionError=False,
                MaximumRetryAttempts=_MAX_RETRIES,
                MaximumRecordAgeInSeconds=_MAX_RECORD_AGE_S,
                DestinationConfig={"OnFailure": {"Destination": queue["arn"]}})

    msgs = _receive_until(ctx, queue["url"], lambda g: len(g) >= 1, timeout_s=_EFFECT_BUDGET_S,
                          description="the OnFailure record for the exhausted batch on the SQS queue")
    # Drain to silence BEFORE claiming "exactly one": _receive_until returns at the first message,
    # so one record per failed attempt would otherwise go uncounted.
    msgs += _drain_quiet(ctx, queue["url"])
    assert len(msgs) == 1, f"one exhausted batch must yield one OnFailure record, got {msgs!r}"
    raw, body = msgs[0]["raw"], msgs[0]["body"]

    item = ddb.get_item(TableName=sink["name"], Key={"pk": {"S": "log"}},
                        ConsistentRead=True)["Item"]
    entries = [json.loads(e["S"]) for e in item["entries"]["L"]]
    failing = [e for e in entries if e["ok"] == 0]
    trail = [(e["b"], e["ok"]) for e in entries]
    # BatchSize is a maximum, so the failed batch is whichever poisoned batch the function saw.
    assert len(failing) == _MAX_RETRIES + 1, (
        f"MaximumRetryAttempts={_MAX_RETRIES} means {_MAX_RETRIES + 1} failing attempts; trail={trail!r}"
    )
    batch = failing[0]["b"]
    assert failing[1]["b"] == batch, f"the retry must carry the same batch; trail={trail!r}"
    start = batch[0] if batch else -1
    assert batch == _VERSIONS[start:start + len(batch)] and _POISON in batch, (
        f"the failed batch must be a contiguous, in-order run of {_VERSIONS!r} holding the poison "
        f"version {_POISON}; trail={trail!r}"
    )
    first_fail = next(i for i, e in enumerate(entries) if e["ok"] == 0)
    before = [v for e in entries[:first_fail] for v in e["b"]]
    assert before == _VERSIONS[:start], (
        f"the records ahead of the failed batch must be processed first, once each and in order: "
        f"expected {_VERSIONS[:start]!r}, trail={trail!r}"
    )
    seqs = failing[0]["seqs"]
    assert failing[1]["seqs"] == seqs, (
        f"the retry must carry the same stream records: {failing[0]['seqs']!r} vs {failing[1]['seqs']!r}"
    )

    # --- it is the pointer, for the right source type, and never the data ---
    assert "DDBStreamBatchInfo" in body, (
        f"a DynamoDB-streams ESM's OnFailure record must carry DDBStreamBatchInfo; keys were "
        f"{sorted(body)!r}"
    )
    assert "KinesisBatchInfo" not in body, (
        f"a DynamoDB-streams source must not be described as Kinesis: keys {sorted(body)!r}"
    )
    assert marker not in raw, (
        f"the SQS OnFailure record is a POINTER and must not contain the item images, yet the body "
        f"contains the item attribute {marker!r}: {raw!r}"
    )

    info = body["DDBStreamBatchInfo"]
    shard_ids = {s["ShardId"] for s in
                 streams.describe_stream(StreamArn=source["stream_arn"])["StreamDescription"]["Shards"]}
    assert info.get("shardId") in shard_ids, (
        f"DDBStreamBatchInfo.shardId must name a shard of the source stream {sorted(shard_ids)!r}, got "
        f"{info.get('shardId')!r}"
    )
    expected = {"startSequenceNumber": seqs[0], "endSequenceNumber": seqs[-1],
                "batchSize": len(batch), "streamArn": source["stream_arn"]}
    got = {k: info.get(k) for k in expected}
    assert got == expected, (
        f"DDBStreamBatchInfo must point at exactly the failed batch:\nexpected {expected!r}\n"
        f"got      {got!r}\nfull body {body!r}"
    )

    rc = body.get("requestContext") or {}
    assert rc.get("condition") == "RetryAttemptsExhausted", (
        f"with MaximumRetryAttempts={_MAX_RETRIES} and MaximumRecordAgeInSeconds={_MAX_RECORD_AGE_S} "
        f"the retry bound fires first, so condition must be RetryAttemptsExhausted; got "
        f"{rc.get('condition')!r} in {body!r}"
    )
    assert rc.get("approximateInvokeCount") == _MAX_RETRIES + 1, (
        f"approximateInvokeCount must be MaximumRetryAttempts + 1 = {_MAX_RETRIES + 1}, got "
        f"{rc.get('approximateInvokeCount')!r}"
    )
    assert str(rc.get("functionArn", "")).split(":")[6:7] == [fn["name"]], (
        f"requestContext.functionArn must name the failing function {fn['name']!r}, got "
        f"{rc.get('functionArn')!r}"
    )
    assert (body.get("responseContext") or {}).get("functionError") == "Unhandled", (
        f"a raised exception is reported as functionError Unhandled, got {body.get('responseContext')!r}"
    )

    # --- and the pointer resolves to those records ---
    it = streams.get_shard_iterator(StreamArn=source["stream_arn"], ShardId=info["shardId"],
                                    ShardIteratorType="AT_SEQUENCE_NUMBER",
                                    SequenceNumber=info["startSequenceNumber"])["ShardIterator"]
    resolved: list[dict] = []
    deadline = time.monotonic() + 30
    while len(resolved) < info["batchSize"] and it and time.monotonic() < deadline:
        page = streams.get_records(ShardIterator=it, Limit=info["batchSize"] - len(resolved))
        resolved += page["Records"]
        it = page.get("NextShardIterator")
    assert [r["dynamodb"]["SequenceNumber"] for r in resolved] == seqs, (
        f"dereferencing the pointer from startSequenceNumber for batchSize records must yield the "
        f"failed batch {seqs!r}; got {[r['dynamodb']['SequenceNumber'] for r in resolved]!r}"
    )
    assert [int(r["dynamodb"]["NewImage"]["v"]["N"]) for r in resolved] == batch, (
        f"the dereferenced stream records must be the failed batch's mutations {batch!r}"
    )
    assert resolved[-1]["dynamodb"]["SequenceNumber"] == info["endSequenceNumber"], (
        f"the batch's last record must be endSequenceNumber {info['endSequenceNumber']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _err(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate holds. RAISES on timeout -- never returns the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _swallow(fn) -> None:
    """Teardown-only: an already-gone resource is fine; anything else is a named leak."""
    try:
        fn()
    except ClientError as exc:
        if _err(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"teardown step failed: {exc}") from exc


def _create_table(ctx, kind: str) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, kind)
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _swallow(lambda: ddb.delete_table(TableName=name)))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _err(exc) != "NoSuchEntity":
            raise RuntimeError(f"IAM role {role_name}: {exc}") from exc


def _reap_log_group(ctx, fn_name: str) -> None:
    """delete_function leaves /aws/lambda/<fn>, and a buffered flush can RECREATE it after a
    delete, so reap in a loop until it stays absent for three consecutive reads."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    deadline = time.monotonic() + 45
    absent = 0
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
            absent = 0
        except ClientError as exc:
            if _err(exc) != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group}: {exc}") from exc
            absent += 1
            if absent >= 3:
                return
        time.sleep(5)
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_lambda(ctx, handler_code: str, *, statements: list[dict], env: dict) -> dict[str, str]:
    """A Lambda plus an execution role scoped to `statements`; logs are always allowed."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    policy = [{"Effect": "Allow",
               "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
               "Resource": "arn:aws:logs:*:*:*"}]
    policy += [{"Effect": "Allow", **s} for s in statements]
    role_name = _xname(ctx, "role")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy}))

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code).strip() + "\n")
    name = _xname(ctx, "fn")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))

    def _attempt():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=30, MemorySize=128, Environment={"Variables": env},
                Tags=dict(_MANAGED_TAGS),
            )
        except ClientError as exc:
            if _err(exc) == "InvalidParameterValueException":   # fresh role not yet assumable
                return None
            raise

    created = _poll_until(_attempt, lambda r: r is not None, timeout_s=90, interval_s=4.0,
                          description=f"CreateFunction {name} past the role-propagation window")
    ctx.on_cleanup(lambda: _swallow(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name),
                lambda c: c.get("State") == "Active", timeout_s=120, interval_s=3.0,
                description=f"Lambda {name} State Active")
    return {"name": name, "arn": created["FunctionArn"]}


def _delete_esm(ctx, uuid_: str) -> None:
    """An ESM still Creating/Enabling refuses deletion with ResourceInUseException; retry, bounded."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            lam.delete_event_source_mapping(UUID=uuid_)
            return
        except ClientError as exc:
            if _err(exc) == "ResourceNotFoundException":
                return
            if _err(exc) != "ResourceInUseException":
                raise RuntimeError(f"event source mapping {uuid_}: {exc}") from exc
        time.sleep(5)
    raise RuntimeError(f"event source mapping {uuid_} still in use after 90s")


def _create_esm(ctx, fn_name: str, source_arn: str, **params) -> str:
    """CreateEventSourceMapping, retried while a fresh role's permissions propagate (bounded).

    Does not wait for Enabled: the downstream effect wait covers activation."""
    lam = ctx.client("lambda")
    seen: list[str] = []

    def _attempt():
        try:
            return lam.create_event_source_mapping(FunctionName=fn_name, EventSourceArn=source_arn,
                                                   Enabled=True, **params)
        except ClientError as exc:
            if _err(exc) == "InvalidParameterValueException":
                seen.append(str(exc))
                return None
            raise

    try:
        resp = _poll_until(_attempt, lambda r: r is not None, timeout_s=90, interval_s=5.0,
                           description="CreateEventSourceMapping past IAM propagation")
    except AssertionError as exc:
        raise AssertionError(f"{exc}; last refusal {seen[-1:]!r}") from None
    ctx.on_cleanup(lambda: _delete_esm(ctx, resp["UUID"]))
    return resp["UUID"]


def _create_queue(ctx) -> dict[str, str]:
    """The OnFailure destination: a standard queue only this check writes to or reads."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "onfail"), tags=dict(_MANAGED_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: _swallow(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _receive_until(ctx, url: str, predicate, *, timeout_s: float, description: str) -> list[dict]:
    """Long-poll the queue, deleting what it reads, until predicate(all bodies so far) holds."""
    sqs = ctx.client("sqs")
    got: list[dict] = []

    def _probe():
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=10).get("Messages", []):
            got.append({"raw": m["Body"], "body": json.loads(m["Body"])})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        return got

    return _poll_until(_probe, predicate, timeout_s=timeout_s, interval_s=0.0,
                       description=description)


def _drain_quiet(ctx, url: str, *, quiet_polls: int = 2, timeout_s: float = 60) -> list[dict]:
    """Read until `quiet_polls` consecutive 10s long polls return nothing; return what was read."""
    sqs = ctx.client("sqs")
    got: list[dict] = []
    quiet = 0
    deadline = time.monotonic() + timeout_s
    while quiet < quiet_polls:
        assert time.monotonic() < deadline, (
            f"queue {url} never went quiet within {timeout_s}s; read {len(got)!r} messages"
        )
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=10).get("Messages", [])
        quiet = 0 if msgs else quiet + 1
        for m in msgs:
            got.append({"raw": m["Body"], "body": json.loads(m["Body"])})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


def _create_stream_table(ctx) -> dict[str, str]:
    """A source table with a NEW_IMAGE stream; the stream ARN is asserted, not assumed."""
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, "src")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _swallow(lambda: ddb.delete_table(TableName=name)))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    stream_arn = resp["TableDescription"].get("LatestStreamArn")
    assert stream_arn, f"CreateTable with StreamEnabled must mint a LatestStreamArn, got {stream_arn!r}"
    return {"name": name, "arn": resp["TableDescription"]["TableArn"], "stream_arn": stream_arn}



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
