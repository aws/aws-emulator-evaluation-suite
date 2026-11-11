"""kinesis-esm-batching-window-gathers-more-records-per-invoke-than-an-immediate-mapping."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-batching-window-gathers-more-records-per-invoke-than-an-immediate-mapping"
GROUP = "event-source-mapping"
SERVICES = ["kinesis", "lambda"]

_SAME_BATCH_SIZE = 50
_WINDOW_S = 8
_TRICKLE_N = 10
_TRICKLE_GAP_S = 1.2

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
            tag: process.env.ARM_TAG,
            size: records.length,
            seqs: records.map((r) => r.kinesis.sequenceNumber),
        })),
    }));
    return { processed: records.length };
};
"""


# timing:real-time — buffer: 8 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With BatchSize held equal, MaximumBatchingWindowInSeconds=8 gathers strictly more records
    per invocation than MaximumBatchingWindowInSeconds=0 (invoke as soon as records are available)
    against the identical trickle of arrivals.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html#invocation-eventsourcemapping-batching
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html#kinesis-polling-and-batching
    """
    kin = ctx.client("kinesis")
    immediate_src = _stream(ctx)
    windowed_src = _stream(ctx)
    sink = _stream(ctx)
    role = _execution_role(ctx, [immediate_src, windowed_src], sink)
    # One shared reap, registered before either function exists, so LIFO runs it LAST -- after
    # both delete_function calls below.
    log_group_names: list[str] = []
    ctx.on_cleanup(lambda: _reap_log_groups(ctx.client("logs"), log_group_names))
    immediate_fn = _function(ctx, role["arn"], _HANDLER,
                             env={"SINK_STREAM": sink["name"], "ARM_TAG": "immediate"},
                             log_group_names=log_group_names)
    windowed_fn = _function(ctx, role["arn"], _HANDLER,
                            env={"SINK_STREAM": sink["name"], "ARM_TAG": "windowed"},
                            log_group_names=log_group_names)

    immediate_esm = _mapping(ctx, EventSourceArn=immediate_src["arn"], FunctionName=immediate_fn["name"],
                             StartingPosition="TRIM_HORIZON", BatchSize=_SAME_BATCH_SIZE,
                             MaximumBatchingWindowInSeconds=0)
    windowed_esm = _mapping(ctx, EventSourceArn=windowed_src["arn"], FunctionName=windowed_fn["name"],
                            StartingPosition="TRIM_HORIZON", BatchSize=_SAME_BATCH_SIZE,
                            MaximumBatchingWindowInSeconds=_WINDOW_S)
    assert immediate_esm["MaximumBatchingWindowInSeconds"] == 0, immediate_esm
    assert windowed_esm["MaximumBatchingWindowInSeconds"] == _WINDOW_S, windowed_esm

    def _batches(tag):
        return [b for b in _sink_batches(ctx, sink) if b["tag"] == tag]

    # A mapping reaching State=Enabled is a control-plane fact; its poller can still take time to
    # start actively fetching. One sentinel record per arm, held until each poller visibly drains
    # it, means the timed trickle below measures batching -- not startup lag -- for both arms.
    warmup_seq = {}
    for tag, src in (("immediate", immediate_src), ("windowed", windowed_src)):
        warmup_seq[tag] = kin.put_record(StreamName=src["name"], PartitionKey="warmup",
                                         Data=b'{"warmup": true}')["SequenceNumber"]
    for tag in ("immediate", "windowed"):
        _poll(lambda t=tag: _batches(t), lambda bs, s=warmup_seq[tag]: s in {q for b in bs for q in b["seqs"]},
             timeout_s=180, interval_s=3, what=f"the {tag} ESM's poller to drain its warmup record")

    # Both streams are fed the SAME trickle concurrently (one put alternating between them per
    # tick), so neither arm's batching has a head start the other lacks.
    put = {"immediate": [], "windowed": []}
    for i in range(_TRICKLE_N):
        for tag, src in (("immediate", immediate_src), ("windowed", windowed_src)):
            seq = kin.put_record(StreamName=src["name"], PartitionKey=f"pk-{i}",
                                 Data=json.dumps({"i": i}).encode())["SequenceNumber"]
            put[tag].append(seq)
        time.sleep(_TRICKLE_GAP_S)

    def _trickle_batches(tag):
        """``tag``'s batches with the warmup record's seq (and any now-empty batch) stripped."""
        out = []
        for b in _batches(tag):
            seqs = [s for s in b["seqs"] if s != warmup_seq[tag]]
            if seqs:
                out.append({"seqs": seqs, "size": len(seqs)})
        return out

    immediate_batches = _poll(lambda: _trickle_batches("immediate"),
        lambda bs: set(put["immediate"]) <= {s for b in bs for s in b["seqs"]},
        timeout_s=180, interval_s=3, what="the immediate ESM to deliver every trickled record")
    windowed_batches = _poll(lambda: _trickle_batches("windowed"),
        lambda bs: set(put["windowed"]) <= {s for b in bs for s in b["seqs"]},
        timeout_s=180, interval_s=3, what="the windowed ESM to deliver every trickled record")

    assert immediate_batches and windowed_batches, (
        f"both ESMs must have delivered something: immediate={len(immediate_batches)!r} "
        f"batches, windowed={len(windowed_batches)!r} batches"
    )
    immediate_mean = sum(b["size"] for b in immediate_batches) / len(immediate_batches)
    windowed_mean = sum(b["size"] for b in windowed_batches) / len(windowed_batches)
    assert windowed_mean > immediate_mean, (
        f"a {_WINDOW_S}s batching window fed the same {_TRICKLE_GAP_S}s trickle as an immediate "
        f"mapping must gather more records per invocation on average: windowed mean="
        f"{windowed_mean!r} over {[b['size'] for b in windowed_batches]!r}, immediate mean="
        f"{immediate_mean!r} over {[b['size'] for b in immediate_batches]!r}"
    )
    assert len(windowed_batches) < len(immediate_batches), (
        f"gathering more records per batch must mean fewer invocations for the same "
        f"{_TRICKLE_N} records: windowed invoked {len(windowed_batches)!r} times, immediate "
        f"invoked {len(immediate_batches)!r} times"
    )
    assert max(b["size"] for b in windowed_batches) >= 2, (
        f"the windowed mapping never batched more than one record per invocation: "
        f"{[b['size'] for b in windowed_batches]!r} -- the window had no observable effect"
    )


# ===== helpers =====


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
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
        zf.writestr("index.js", textwrap.dedent(code))
    return buf.getvalue()


def _execution_role(ctx, sources, sink) -> dict:
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
         "Action": ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary",
                    "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:ListShards",
                    "kinesis:ListStreams"],
         "Resource": [s["arn"] for s in sources]},
        {"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": sink["arn"]},
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:{role['Arn'].split(':')[1]}:logs:*:*:*"},
    ]
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
        "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, role_arn, code, *, env, log_group_names) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "nodejs22.x", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": 30,
              "MemorySize": 256, "Environment": {"Variables": env}, "Tags": {"sim2real": CHECK}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in err.get(
                    "Message", ""):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
               what="CreateFunction accepts the fresh execution role")
    log_group_names.append(f"/aws/lambda/{name}")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                lambda c: c.get("State", "Active") in ("Active", "Failed"),
                timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _reap_log_groups(logs, names: list, *, reads: int = 2, interval_s: float = 3.0,
                     budget_s: float = 45.0) -> None:
    """Re-delete every name in ``names`` together until each has ``reads`` consecutive absent
    reads."""
    deadline = time.monotonic() + budget_s
    clean_reads = {name: 0 for name in names}
    while any(c < reads for c in clean_reads.values()):
        for name in names:
            if clean_reads[name] >= reads:
                continue
            groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
            if any(g["logGroupName"] == name for g in groups):
                clean_reads[name] = 0
                try:
                    logs.delete_log_group(logGroupName=name)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                clean_reads[name] += 1
        if any(c < reads for c in clean_reads.values()):
            if time.monotonic() > deadline:
                stragglers = [n for n, c in clean_reads.items() if c < reads]
                raise AssertionError(
                    f"log group(s) still present after {budget_s}s of deletes: {stragglers!r}")
            time.sleep(interval_s)


def _mapping(ctx, **kwargs) -> dict:
    lam = ctx.client("lambda")

    def create():
        try:
            return lam.create_event_source_mapping(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and (
                    "does not have permissions to call" in err.get("Message", "")):
                return None
            raise

    esm = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
               what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    _poll(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == "Enabled",
         timeout_s=120, interval_s=2, what=f"mapping {uuid} reaches Enabled")
    return esm


def _stream(ctx, shards=1) -> dict:
    kin = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-ks-")
    kin.create_stream(StreamName=name, ShardCount=shards,
                      StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(_teardown(lambda: kin.delete_stream(StreamName=name,
                                                       EnforceConsumerDeletion=True),
                             "ResourceNotFoundException"))
    kin.get_waiter("stream_exists").wait(StreamName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    desc = kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    kin.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    out = {"name": name, "arn": desc["StreamARN"]}
    return out


def _sink_batches(ctx, sink) -> list:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
