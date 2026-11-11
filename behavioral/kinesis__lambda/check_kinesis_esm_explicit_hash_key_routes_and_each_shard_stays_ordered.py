"""kinesis-esm-explicit-hash-key-routes-and-each-shard-stays-ordered."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-explicit-hash-key-routes-and-each-shard-stays-ordered"
GROUP = "event-propagation"
SERVICES = ["kinesis", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """On a two-shard stream, records pinned by ExplicitHashKey under one partition key land in and
    reach the function from the named shard with eventID <ShardId>:<sequenceNumber>, and each
    shard's records arrive in put order with increasing sequence numbers.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html
    """
    kin = ctx.client("kinesis")
    src = _stream(ctx, shards=2)
    sink = _stream(ctx)
    shards = kin.list_shards(StreamName=src["name"])["Shards"]
    assert len(shards) == 2, f"a two-shard stream lists {len(shards)} shards"
    role = _stream_role(ctx, src, sink)
    fn = _function(ctx, role["arn"], _SINK_HANDLER, env={"SINK": sink["name"]})
    _mapping(ctx, EventSourceArn=src["arn"], FunctionName=fn["name"],
             StartingPosition="TRIM_HORIZON", BatchSize=2)

    run_id = ctx.unique_name("")
    put_order = {s["ShardId"]: [] for s in shards}
    for i in range(8):
        shard = shards[i % 2]
        r = kin.put_record(StreamName=src["name"], PartitionKey="same-key",
                           ExplicitHashKey=shard["HashKeyRange"]["StartingHashKey"],
                           Data=json.dumps({"i": i, "run": run_id}).encode())
        assert r["ShardId"] == shard["ShardId"], (
            f"PutRecord with the StartingHashKey of {shard['ShardId']} landed in {r['ShardId']}")
        put_order[r["ShardId"]].append(r["SequenceNumber"])

    want = {seq for seqs in put_order.values() for seq in seqs}

    def delivered(batches):
        return [r for b in batches for r in b["records"] if r["kinesis"]["sequenceNumber"] in want]

    batches = _wait_batches(ctx, sink, lambda bs: {r["kinesis"]["sequenceNumber"]
                                                   for r in delivered(bs)} >= want,
                            timeout_s=180, what="all eight records reach the function")
    for shard_id, seqs in put_order.items():
        got = []
        for r in delivered(batches):
            if r["eventID"].split(":", 1)[0] == shard_id and r["kinesis"]["sequenceNumber"] not in got:
                got.append(r["kinesis"]["sequenceNumber"])
        assert got == seqs, f"{shard_id}: delivered order {got!r} != put order {seqs!r}"
        assert [int(s) for s in got] == sorted(int(s) for s in got), (
            f"{shard_id}: sequence numbers not increasing: {got!r}")
    for r in delivered(batches):
        assert r["eventID"] == f"{r['eventID'].split(':', 1)[0]}:{r['kinesis']['sequenceNumber']}", (
            f"eventID {r['eventID']!r} does not end in its sequenceNumber")


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


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN, never a literal."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"unparseable caller ARN {arn!r}"
    return parts[1]


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, env=None, timeout=30) -> dict:
    """A python3.12 function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "python3.12", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}
    if env:
        kwargs["Environment"] = {"Variables": env}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _mapping(ctx, **kwargs) -> dict:
    """CreateEventSourceMapping through the role-propagation window, then poll it to Enabled."""
    lam = ctx.client("lambda")

    def create():
        try:
            return lam.create_event_source_mapping(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    esm = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    want = "Enabled" if kwargs.get("Enabled", True) else "Disabled"
    _poll(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == want,
          timeout_s=120, interval_s=2, what=f"mapping {uuid} reaches {want}")
    return esm


def _stream(ctx, shards=1) -> dict:
    """A provisioned stream of ours with ``shards`` shards, ACTIVE, its delete registered."""
    kin = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-ks-")
    kin.create_stream(StreamName=name, ShardCount=shards,
                      StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(_teardown(lambda: kin.delete_stream(StreamName=name,
                                                       EnforceConsumerDeletion=True),
                             "ResourceNotFoundException"))
    kin.get_waiter("stream_exists").wait(StreamName=name,
                                         WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    desc = kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    kin.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return {"name": name, "arn": desc["StreamARN"]}


_SINK_HANDLER = """\
import json, os
import boto3

def handler(event, context):
    boto3.client("kinesis").put_record(StreamName=os.environ["SINK"], PartitionKey="sink",
                                       Data=json.dumps({"tag": os.environ.get("TAG", ""),
                                                        "records": event["Records"]}).encode())
    return {"n": len(event["Records"])}
"""


def _stream_role(ctx, src, sink) -> dict:
    return _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary",
                                       "kinesis:GetRecords", "kinesis:GetShardIterator",
                                       "kinesis:ListShards", "kinesis:ListStreams"],
         "Resource": src["arn"]},
        {"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": sink["arn"]},
    ])


def _sink_batches(ctx, sink) -> list:
    """Every invocation's forwarded {tag, records} on the one-shard sink stream, oldest first."""
    kin = ctx.client("kinesis")
    shard = kin.list_shards(StreamName=sink["name"])["Shards"][0]["ShardId"]
    it = kin.get_shard_iterator(StreamName=sink["name"], ShardId=shard,
                                ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    out = []
    while it:
        page = kin.get_records(ShardIterator=it, Limit=1000)
        out.extend(json.loads(r["Data"]) for r in page["Records"])
        if not page["Records"] and page.get("MillisBehindLatest", 0) == 0:
            break
        it = page.get("NextShardIterator")
    return out


def _wait_batches(ctx, sink, done, *, timeout_s, what) -> list:
    return _poll(lambda: _sink_batches(ctx, sink), done, timeout_s=timeout_s, interval_s=3,
                 what=what)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
