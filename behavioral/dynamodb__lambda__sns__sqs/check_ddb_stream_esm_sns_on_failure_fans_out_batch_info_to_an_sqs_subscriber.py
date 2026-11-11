"""ddb-stream-esm-sns-on-failure-fans-out-batch-info-to-an-sqs-subscriber."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-esm-sns-on-failure-fans-out-batch-info-to-an-sqs-subscriber"
GROUP = "error-propagation"
SERVICES = ["dynamodb", "lambda", "sns", "sqs"]

_EFFECT_BUDGET_S = 200


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB-streams ESM whose OnFailure destination names an SNS topic fans the exhausted
    batch's DDBStreamBatchInfo pointer out, wrapped in the topic's own envelope, to every SQS
    queue subscribed to it; a record the handler never fails on reaches no destination at all.
    """
    ddb = ctx.client("dynamodb")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    source = _create_stream_table(ctx)
    topic_arn = _create_topic(ctx)
    queue = _create_subscribed_queue(ctx, topic_arn)

    code = """
    def handler(event, context):
        for rec in event["Records"]:
            if rec["dynamodb"]["NewImage"].get("fail", {}).get("S") == "true":
                raise RuntimeError("deliberate-failure")
        return {"ok": True}
    """
    fn = _create_lambda(
        ctx, code,
        statements=[
            {"Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator",
                        "dynamodb:DescribeStream", "dynamodb:ListStreams"],
             "Resource": f"{source['arn']}/stream/*"},
            {"Action": ["sns:Publish"], "Resource": topic_arn},
        ],
    )

    # A healthy record first, in the same shard ahead of the poisoned one, so any destination
    # traffic it caused would arrive before the poisoned record's.
    ddb.put_item(TableName=source["name"], Item={"pk": {"S": "healthy-1"}, "fail": {"S": "false"}})
    _create_esm(ctx, fn["name"], source["stream_arn"],
                StartingPosition="TRIM_HORIZON", BatchSize=1,
                MaximumBatchingWindowInSeconds=0, MaximumRetryAttempts=0,
                DestinationConfig={"OnFailure": {"Destination": topic_arn}})

    # Now the always-failing record, on the same mapping.
    ddb.put_item(TableName=source["name"], Item={"pk": {"S": "poison-1"}, "fail": {"S": "true"}})

    msgs = _receive_until(ctx, sqs, queue["url"], lambda g: len(g) >= 1, timeout_s=_EFFECT_BUDGET_S,
                          description="the SNS-fanned-out OnFailure record for the poisoned record")
    msgs += _drain_quiet(ctx, sqs, queue["url"])
    assert len(msgs) == 1, f"one exhausted record must yield exactly one fanned-out message, got {msgs!r}"
    envelope = msgs[0]

    # --- it arrived through SNS, not a direct SQS destination ---
    assert envelope.get("Type") == "Notification", (
        f"a queue subscribed to an SNS topic receives the SNS envelope, got keys {sorted(envelope)!r}"
    )
    assert envelope.get("TopicArn") == topic_arn, (
        f"TopicArn must name the destination topic {topic_arn!r}, got {envelope.get('TopicArn')!r}"
    )
    body = json.loads(envelope["Message"])

    # --- the fanned-out payload is the pointer, field by field ---
    assert "DDBStreamBatchInfo" in body, (
        f"a DynamoDB-streams ESM's OnFailure record must carry DDBStreamBatchInfo; keys were "
        f"{sorted(body)!r}"
    )
    info = body["DDBStreamBatchInfo"]
    assert info.get("streamArn") == source["stream_arn"], (
        f"DDBStreamBatchInfo.streamArn must name {source['stream_arn']!r}, got {info.get('streamArn')!r}"
    )
    assert info.get("batchSize") == 1, f"BatchSize=1 means batchSize must be 1, got {info.get('batchSize')!r}"
    assert info.get("startSequenceNumber") == info.get("endSequenceNumber"), (
        f"a one-record batch's start and end sequence numbers must match: {info!r}"
    )
    streams = ctx.client("dynamodbstreams")
    shard_ids = {s["ShardId"] for s in
                 streams.describe_stream(StreamArn=source["stream_arn"])["StreamDescription"]["Shards"]}
    assert info.get("shardId") in shard_ids, (
        f"DDBStreamBatchInfo.shardId must name a shard of {source['stream_arn']!r} ({sorted(shard_ids)!r}), "
        f"got {info.get('shardId')!r}"
    )

    rc = body.get("requestContext") or {}
    assert rc.get("condition") == "RetryAttemptsExhausted", (
        f"with MaximumRetryAttempts=0 the retry bound fires on the first attempt, so condition must "
        f"be RetryAttemptsExhausted; got {rc.get('condition')!r} in {body!r}"
    )
    assert rc.get("approximateInvokeCount") == 1, (
        f"MaximumRetryAttempts=0 means exactly one invocation; approximateInvokeCount must be 1, got "
        f"{rc.get('approximateInvokeCount')!r}"
    )
    assert str(rc.get("functionArn", "")).split(":")[6:7] == [fn["name"]], (
        f"requestContext.functionArn must name the failing function {fn['name']!r}, got "
        f"{rc.get('functionArn')!r}"
    )
    rsp = body.get("responseContext") or {}
    assert rsp.get("functionError") == "Unhandled", (
        f"a raised exception is reported as functionError Unhandled, got {rsp!r}"
    )

    # --- and the pointer resolves to the poisoned record, never to "healthy-1" ---
    it = streams.get_shard_iterator(StreamArn=source["stream_arn"], ShardId=info["shardId"],
                                    ShardIteratorType="AT_SEQUENCE_NUMBER",
                                    SequenceNumber=info["startSequenceNumber"])["ShardIterator"]
    page = streams.get_records(ShardIterator=it, Limit=info["batchSize"])
    resolved = page["Records"]
    assert len(resolved) == 1, f"dereferencing a batchSize=1 pointer must yield one record, got {resolved!r}"
    assert resolved[0]["dynamodb"]["NewImage"]["pk"]["S"] == "poison-1", (
        f"the resolved record must be the poisoned one, got {resolved[0]['dynamodb']['NewImage']!r}"
    )


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate holds; raises TimeoutError at the deadline, capped by the run
    budget."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not observed within {timeout_s:.0f}s; last saw {last!r}")


def _err(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _swallow(fn) -> None:
    """Teardown-only: an already-gone resource is fine; anything else is a named leak."""
    try:
        fn()
    except ClientError as exc:
        if _err(exc) not in ("ResourceNotFoundException", "NotFound",
                             "AWS.SimpleQueueService.NonExistentQueue"):
            raise RuntimeError(f"teardown step failed: {exc}") from exc


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _tags_kv(check: str) -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": check}]


def _create_stream_table(ctx) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, "src")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        Tags=_tags_kv(CHECK),
    )
    ctx.on_cleanup(lambda: _swallow(lambda: ddb.delete_table(TableName=name)))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    stream_arn = resp["TableDescription"].get("LatestStreamArn")
    assert stream_arn, f"CreateTable with StreamEnabled must mint a LatestStreamArn, got {stream_arn!r}"
    return {"name": name, "arn": resp["TableDescription"]["TableArn"], "stream_arn": stream_arn}


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    name = _xname(ctx, "topic")
    arn = sns.create_topic(Name=name, Tags=_tags_kv(CHECK))["TopicArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sns.delete_topic(TopicArn=arn)))
    return arn


def _create_subscribed_queue(ctx, topic_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    url = sqs.create_queue(QueueName=_xname(ctx, "onfail"), tags=dict(
        {kv["Key"]: kv["Value"] for kv in _tags_kv(CHECK)}
    ))["QueueUrl"]
    ctx.on_cleanup(lambda: _swallow(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))
    return {"url": url, "arn": arn}


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


def _create_lambda(ctx, handler_code: str, *, statements: list[dict]) -> dict[str, str]:
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
        Tags=_tags_kv(CHECK),
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
                Timeout=30, MemorySize=128,
                Tags={kv["Key"]: kv["Value"] for kv in _tags_kv(CHECK)},
            )
        except ClientError as exc:
            if (_err(exc) == "InvalidParameterValueException"
                    and "cannot be assumed" in exc.response["Error"].get("Message", "")):
                return None
            raise

    created = _poll_until(ctx, _attempt, lambda r: r is not None, timeout_s=90, interval_s=4.0,
                          description=f"CreateFunction {name} past the role-propagation window")
    ctx.on_cleanup(lambda: _swallow(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(ctx, lambda: lam.get_function_configuration(FunctionName=name),
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
        resp = _poll_until(ctx, _attempt, lambda r: r is not None, timeout_s=90, interval_s=5.0,
                           description="CreateEventSourceMapping past IAM propagation")
    except TimeoutError as exc:
        raise TimeoutError(f"{exc}; last refusal {seen[-1:]!r}") from None
    ctx.on_cleanup(lambda: _delete_esm(ctx, resp["UUID"]))
    return resp["UUID"]


def _receive(sqs, url: str) -> list[dict]:
    got = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=10).get(
        "Messages", []
    ):
        got.append(json.loads(m["Body"]))
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


def _receive_until(ctx, sqs, url: str, predicate, *, timeout_s: float, description: str) -> list[dict]:
    got: list[dict] = []

    def _probe():
        got.extend(_receive(sqs, url))
        return got

    return _poll_until(ctx, _probe, predicate, timeout_s=timeout_s, interval_s=0.0, description=description)


def _drain_quiet(ctx, sqs, url: str, *, quiet_polls: int = 2, timeout_s: float = 60) -> list[dict]:
    """Read until `quiet_polls` consecutive 10s long polls return nothing; return what was read."""
    got: list[dict] = []
    quiet = 0
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while quiet < quiet_polls:
        if time.monotonic() >= deadline:
            break
        msgs = _receive(sqs, url)
        quiet = 0 if msgs else quiet + 1
        got.extend(msgs)
    return got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
