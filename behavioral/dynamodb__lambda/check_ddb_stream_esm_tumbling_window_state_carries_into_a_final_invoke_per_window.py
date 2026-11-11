"""ddb-stream-esm-tumbling-window-state-carries-into-a-final-invoke-per-window."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from datetime import datetime
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-stream-esm-tumbling-window-state-carries-into-a-final-invoke-per-window"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda"]

WINDOW_S = 15
BATCH_SIZE = 2
N_RECORDS = 8

_WINDOW_HANDLER = """\
import json, os, uuid
import boto3

def handler(event, context):
    state = event.get("state") or {}
    recs = event.get("Records") or []
    out = {"n": str(int(state.get("n", "0")) + len(recs))}
    boto3.client("sqs").send_message(
        QueueUrl=os.environ["SINK"],
        MessageGroupId="sim2real-sink",
        MessageDeduplicationId=str(uuid.uuid4()),
        MessageBody=json.dumps({"window": event.get("window"), "stateIn": state, "stateOut": out,
                                "final": event.get("isFinalInvokeForWindow"),
                                "early": event.get("isWindowTerminatedEarly"),
                                "shardId": event.get("shardId"),
                                "records": [{"id": r["dynamodb"]["Keys"]["id"]["S"],
                                             "ts": r["dynamodb"]["ApproximateCreationDateTime"]}
                                            for r in recs]}),
    )
    return {"state": out}
"""


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


# timing:real-time — buffer: 15 s https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-windows.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A DynamoDB Streams ESM with TumblingWindowInSeconds opens each window with empty state,
    hands the returned state to later invocations of that window, and ends it with an
    isFinalInvokeForWindow invocation whose state counts every record delivered at least once.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html
    """
    ddb = ctx.client("dynamodb")
    table_name, stream_arn = _stream_table(ctx)
    sink = _queue(ctx)
    role = _stream_role(ctx, stream_arn, sink["arn"])
    fn = _function(ctx, role["arn"], _WINDOW_HANDLER, env={"SINK": sink["url"]})
    esm = _mapping(ctx, EventSourceArn=stream_arn, FunctionName=fn["name"],
                  StartingPosition="TRIM_HORIZON", BatchSize=BATCH_SIZE,
                  TumblingWindowInSeconds=WINDOW_S)
    assert esm["TumblingWindowInSeconds"] == WINDOW_S, f"mapping echoes {esm['TumblingWindowInSeconds']!r}"

    # The mapping is already Enabled (and its pollers warm) before any item exists, so the backlog
    # lands in the window open when the pollers catch up, in several batches of that window.
    put_ids = [f"sim2real-item-{i}" for i in range(N_RECORDS)]
    for item_id in put_ids:
        ddb.put_item(TableName=table_name, Item={"id": {"S": item_id}})

    def window_key(inv):
        return (inv["shardId"], inv["window"]["start"])

    def closed(invs):
        unwindowed = [inv for inv in invs if not inv.get("window")]
        assert unwindowed == [], f"invocation(s) carried no tumbling window: {unwindowed[:2]!r}"
        seen = {r["id"] for inv in invs for r in inv["records"]}
        open_windows = {window_key(inv) for inv in invs} - {
            window_key(inv) for inv in invs if inv["final"]}
        return set(put_ids) <= seen and not open_windows

    invs = _wait_messages(ctx, sink, closed, timeout_s=300,
                          what="every item is delivered and every window it fell in is closed")

    # Lambda processes each record at least once, so a batch may repeat; every assert below holds
    # under redelivery and fails on a target that drops records or state.
    by_window: dict[tuple, list] = {}
    for inv in invs:
        by_window.setdefault(window_key(inv), []).append(inv)
    for start, seq_invs in by_window.items():
        window = seq_invs[0]["window"]
        assert all(inv["window"] == window for inv in seq_invs), (
            f"window {start}: invocations disagree on its bounds {[i['window'] for i in seq_invs]!r}")
        assert _ts(window["end"]) - _ts(window["start"]) == WINDOW_S, f"window bounds {window!r}"
        assert seq_invs[0]["stateIn"] == {}, f"window {start} opened with state {seq_invs[0]['stateIn']!r}"
        for i, nxt in enumerate(seq_invs[1:], start=1):
            earlier = [{}] + [prev["stateOut"] for prev in seq_invs[:i]]
            assert nxt["stateIn"] in earlier, (
                f"window {start}: an invocation received {nxt['stateIn']!r}, which no earlier "
                f"invocation of the window returned ({earlier!r})")
        final_at = [i for i, inv in enumerate(seq_invs) if inv["final"]]
        assert final_at and all(seq_invs[i]["final"] for i in range(final_at[0], len(seq_invs))), (
            f"window {start}: final flags in order {[inv['final'] for inv in seq_invs]!r}")
        distinct = {r["id"] for inv in seq_invs for r in inv["records"]}
        counted = int(seq_invs[-1]["stateOut"]["n"])
        assert counted >= len(distinct), (
            f"window {start} delivered {len(distinct)} distinct records; the final invocation's "
            f"state counted {counted}")
        assert not any(inv["early"] for inv in seq_invs), f"window {start} terminated early"
        for inv in seq_invs:
            for r in inv["records"]:
                assert _ts(window["start"]) <= r["ts"] < _ts(window["end"]), (
                    f"record arrived at {r['ts']!r}, outside its window {window!r}")
    delivered = {r["id"] for inv in invs for r in inv["records"]}
    assert delivered == set(put_ids), (
        f"delivered ids {sorted(delivered)!r}, expected exactly the {len(put_ids)} put")
    carried = [inv for inv in invs if inv["stateIn"] != {}]
    assert carried, (
        f"no invocation received a carried state, so the hand-off was never exercised; windows "
        f"{list(by_window)!r}")


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


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises TimeoutError naming ``what`` and the last result."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s:.0f}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _stream_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-xsvc-tbl-")
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
        timeout_s=60, interval_s=2.0, what=f"table {name} ACTIVE with a stream",
    )
    return name, desc["LatestStreamArn"]


def _queue(ctx) -> dict[str, str]:
    """A FIFO queue of one implicit message group, so the sink preserves send order."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-") + ".fifo"
    url = sqs.create_queue(QueueName=name, Attributes={"FifoQueue": "true"},
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _stream_role(ctx, stream_arn: str, sink_arn: str) -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
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
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink_arn},
    ]
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
                             "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, role_arn, code, *, env=None, timeout=30) -> dict:
    """A python3.13 function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "python3.13", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}
    if env:
        kwargs["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=3,
               what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                lambda c: c.get("State", "Active") in ("Active", "Failed"),
                timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _mapping(ctx, **kwargs) -> dict:
    """CreateEventSourceMapping through the role-propagation window, then poll it to Enabled."""
    lam = ctx.client("lambda")

    def create():
        try:
            return lam.create_event_source_mapping(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "Cannot access stream" in err["Message"]:
                return None
            raise

    esm = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=3,
               what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    _poll(ctx, lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == "Enabled",
         timeout_s=120, interval_s=2, what=f"mapping {uuid} reaches Enabled")
    return esm


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


def _drain_queue(ctx, queue_url: str, wait_s: int = 3) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _wait_messages(ctx, sink, done, *, timeout_s, what) -> list[dict[str, Any]]:
    accumulated: list[dict[str, Any]] = []
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        accumulated.extend(_drain_queue(ctx, sink["url"]))
        if done(accumulated):
            return accumulated
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s:.0f}s waiting until {what}; last={accumulated!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
