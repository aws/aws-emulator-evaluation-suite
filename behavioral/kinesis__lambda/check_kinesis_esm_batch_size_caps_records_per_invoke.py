"""kinesis-esm-batch-size-caps-records-per-invoke."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-batch-size-caps-records-per-invoke"
GROUP = "event-source-mapping"
SERVICES = ["kinesis", "lambda"]

_BATCH_SIZE = 4
_N_RECORDS = 14
_DELIVERY_BUDGET_S = 180

# A nodejs22.x handler: it only needs to report what it was handed, so the comparison does not
# depend on any one language's runtime behavior.
_HANDLER = """\
const { KinesisClient, PutRecordCommand } = require("@aws-sdk/client-kinesis");
const kinesis = new KinesisClient({});

exports.handler = async (event) => {
    const records = event.Records || [];
    await kinesis.send(new PutRecordCommand({
        StreamName: process.env.SINK_STREAM,
        PartitionKey: "sink",
        Data: Buffer.from(JSON.stringify({
            n: records.length,
            seqs: records.map((r) => r.kinesis.sequenceNumber),
        })),
    }));
    return { processed: records.length };
};
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Kinesis mapping with BatchSize=4 never forwards more than 4 records in a single
    invocation, even when the shard already holds more than 4 unread records, and every record
    is eventually delivered across the resulting invocations.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
    """
    kin = ctx.client("kinesis")
    src = _stream(ctx)
    sink = _stream(ctx)

    put_seqs = set()
    for i in range(_N_RECORDS):
        seq = kin.put_record(StreamName=src["name"], PartitionKey="same-key",
                             Data=json.dumps({"i": i}).encode())["SequenceNumber"]
        put_seqs.add(seq)

    role = _stream_role(ctx, src, sink)
    fn = _function(ctx, role["arn"], sink["name"])
    _mapping(ctx, EventSourceArn=src["arn"], FunctionName=fn["name"],
             StartingPosition="TRIM_HORIZON", BatchSize=_BATCH_SIZE)

    def total(batches):
        return sum(b["n"] for b in batches)

    batches = _wait_batches(ctx, sink, lambda bs: total(bs) >= _N_RECORDS,
                            timeout_s=_budget_s(ctx, _DELIVERY_BUDGET_S),
                            what=f"the sink has forwarded all {_N_RECORDS} records")
    sizes = [b["n"] for b in batches]
    assert all(n <= _BATCH_SIZE for n in sizes), (
        f"an invocation forwarded more than BatchSize={_BATCH_SIZE} records: sizes={sizes!r}")
    assert _BATCH_SIZE in sizes, (
        f"no invocation forwarded a full BatchSize={_BATCH_SIZE} batch: sizes={sizes!r}")
    seen_seqs = {s for b in batches for s in b["seqs"]}
    assert put_seqs <= seen_seqs, (
        f"{len(put_seqs - seen_seqs)} of {_N_RECORDS} put records were never forwarded")


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


def _poll(probe, done, *, timeout_s, interval_s, what, ctx=None):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout.

    A ``timeout_s`` capped by the run budget (`_budget_s`) raises ``TimeoutError`` instead of
    failing once the budget, not the wait's own deadline, is what ended it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    f"{what}: the run budget ended first; not graded; last={last!r}")
            raise AssertionError(
                f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _zip(filename: str, code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


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


def _stream_role(ctx, src, sink) -> dict:
    return _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary",
                                       "kinesis:GetRecords", "kinesis:GetShardIterator",
                                       "kinesis:ListShards", "kinesis:ListStreams"],
         "Resource": src["arn"]},
        {"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": sink["arn"]},
    ])


def _function(ctx, role_arn, sink_name, *, timeout=30) -> dict:
    """A nodejs22.x function from ``_HANDLER``, created through the role-propagation window and
    Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "nodejs22.x", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip("index.js", _HANDLER)},
              "Timeout": timeout, "MemorySize": 256, "Tags": {"sim2real": CHECK},
              "Environment": {"Variables": {"SINK_STREAM": sink_name}}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=_budget_s(ctx, 90), interval_s=2,
                what="CreateFunction accepts the fresh execution role", ctx=ctx)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=_budget_s(ctx, 90), interval_s=2,
                 what=f"function {name} leaves Pending", ctx=ctx)
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
            err = exc.response.get("Error", {})
            unpropagated = err.get("Code") == "InvalidParameterValueException" and (
                "role" in (err.get("Message") or "").lower())
            if unpropagated:
                return None
            raise

    esm = _poll(create, lambda r: r is not None, timeout_s=_budget_s(ctx, 90), interval_s=2,
                what="CreateEventSourceMapping accepts the fresh execution role", ctx=ctx)
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    want = "Enabled" if kwargs.get("Enabled", True) else "Disabled"
    _poll(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == want,
          timeout_s=_budget_s(ctx, 120), interval_s=2,
          what=f"mapping {uuid} reaches {want}", ctx=ctx)
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


def _sink_batches(ctx, sink) -> list:
    """Every invocation's forwarded {n, seqs} on the one-shard sink stream, oldest first."""
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
    return _poll(lambda: _sink_batches(ctx, sink), done, timeout_s=timeout_s, interval_s=2,
                 what=what, ctx=ctx)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
