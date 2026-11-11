"""deep-cwlogs-semantics-deleted-subscription-filter-delivery-blocked."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-deleted-subscription-filter-delivery-blocked"
GROUP = "subscription-delivery"
SERVICES = ["kinesis", "logs"]

_GZIP_MAGIC = b"\x1f\x8b"
_ROUND_BUDGET_S = 60.0
_MAX_ROUNDS_TO_STOP = 3
_MAX_REPAIR_ROUNDS = 6


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Deleting a subscription filter stops its delivery while a sibling filter on the same log
    group keeps delivering to the same Kinesis stream; recreating the filter resumes delivery,
    and events written while it was absent are never delivered retroactively.
    """
    logs = ctx.client("logs")
    stream_name, stream_arn = _create_active_stream(ctx)
    shard_ids = [s["ShardId"] for s in ctx.client("kinesis").list_shards(StreamName=stream_name)["Shards"]]
    role_arn = _create_logs_delivery_role(ctx, stream_arn)

    group = ctx.unique_name("sim2real-xsvc-lg-delsub-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    log_stream = "app"
    logs.create_log_stream(logGroupName=group, logStreamName=log_stream)

    kept = ctx.unique_name("sim2real-xsvc-sf-kept-")
    dropped = ctx.unique_name("sim2real-xsvc-sf-dropped-")

    def _subscribe(name, term):
        _retry_invalid_parameter(
            lambda: logs.put_subscription_filter(
                logGroupName=group, filterName=name, filterPattern=term,
                destinationArn=stream_arn, roleArn=role_arn),
            timeout_s=120.0,
            description=f"PutSubscriptionFilter {name} once the delivery role has propagated",
        )
        ctx.on_cleanup(lambda: _delete_quietly(logs, group, name))

    _subscribe(kept, "keptterm")
    _subscribe(dropped, "droppedterm")

    def _delivered():
        seen = set()
        for env in _read_envelopes(ctx, stream_name, shard_ids):
            if env["messageType"] == "DATA_MESSAGE":
                seen.update(e["message"] for e in env["logEvents"])
        return seen

    # Each round writes one event per filter in the same batch; the surviving filter's event
    # is the barrier that proves the round was processed, so absence needs no sleep.
    def _round(tag):
        k, d = f"keptterm {tag}", f"droppedterm {tag}"
        _put(logs, group, log_stream, [k, d])
        return _poll_until(_delivered, lambda s: k in s, timeout_s=_ROUND_BUDGET_S, interval_s=5.0,
                           description=f"the surviving filter's event {k!r} to arrive"), d

    # Positive control: both filters deliver.
    seen, d0 = _round("r0")
    seen = _poll_until(_delivered, lambda s: d0 in s, timeout_s=_ROUND_BUDGET_S, interval_s=5.0,
                       description=f"the to-be-deleted filter's control event {d0!r} to arrive")

    logs.delete_subscription_filter(logGroupName=group, filterName=dropped)
    remaining = [f["filterName"] for f in logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]]
    assert remaining == [kept], f"after deleting {dropped!r} only {kept!r} may remain; got {remaining!r}"

    # Deletion is eventually consistent: allow up to _MAX_ROUNDS_TO_STOP rounds for delivery
    # to stop, then one more round to prove it stayed stopped.
    stopped_at = None
    written_while_absent = []
    for i in range(1, _MAX_ROUNDS_TO_STOP + 2):
        seen, d = _round(f"r{i}")
        written_while_absent.append(d)
        if stopped_at is None:
            if d not in seen:
                stopped_at = i
            elif i >= _MAX_ROUNDS_TO_STOP:
                raise AssertionError(
                    f"delivery for deleted filter {dropped!r} never stopped: its events "
                    f"{[m for m in written_while_absent if m in seen]!r} kept arriving over {i} rounds")
        elif i > stopped_at:
            break
    assert stopped_at is not None, f"delivery for deleted filter {dropped!r} never stopped"
    late = [m for m in written_while_absent[stopped_at - 1:] if m in seen]
    assert late == [], (
        f"once delivery for the deleted filter stopped (round {stopped_at}) it must stay stopped; "
        f"these were delivered anyway: {late!r}"
    )

    # A recreated filter takes effect after a lag (a marker written right after recreation can
    # miss 90 s), so repair rounds repeat until one of its markers arrives.
    _subscribe(dropped, "droppedterm")
    repaired = None
    for i in range(1, _MAX_REPAIR_ROUNDS + 1):
        seen, d = _round(f"after-recreate-{i}")
        seen = _delivered() if d not in seen else seen
        if any(m.startswith("droppedterm after-recreate-") for m in seen):
            repaired = sorted(m for m in seen if m.startswith("droppedterm after-recreate-"))
            break
    assert repaired, (
        f"the recreated filter {dropped!r} never delivered any of {_MAX_REPAIR_ROUNDS} repair "
        "markers; the destination is reachable (the sibling filter delivered every round)"
    )
    backfilled = [m for m in written_while_absent[stopped_at - 1:] if m in seen]
    assert backfilled == [], (
        f"recreating the filter must not deliver events written while it was absent: {backfilled!r}"
    )


def _delete_quietly(logs, group, name):
    try:
        logs.delete_subscription_filter(logGroupName=group, filterName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _put(logs, group, stream, messages):
    base = int(time.time() * 1000)
    resp = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(messages)])
    assert "rejectedLogEventsInfo" not in resp, f"fixture batch partially rejected: {resp!r}"


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


_NOT_DELIVERED = (
    "Could not deliver test message to specified Kinesis stream. "
    "Check if the given Kinesis stream is in ACTIVE state."
)


def _retry_invalid_parameter(fn, *, timeout_s, description):
    """IAM trust/permission propagation surfaces as InvalidParameterException (Logs test-delivers
    synchronously). Re-raises past the deadline; never swallows."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            propagating = code == "InvalidParameterException" and message == _NOT_DELIVERED
            if not propagating or time.monotonic() >= deadline:
                raise AssertionError(f"{description} failed: {exc.response['Error']!r}") from exc
            time.sleep(5.0)


def _create_active_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-kds-")
    kinesis.create_stream(StreamName=name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"},
                          Tags={"sim2real": "behavioral", "sim2real-check": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE", timeout_s=180.0, interval_s=3.0,
        description=f"stream {name} to reach ACTIVE")
    return name, summary["StreamARN"]


def _create_logs_delivery_role(ctx, stream_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-logs-role-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": "sim2real-check", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="kinesis-write", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"], "Resource": stream_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kinesis-write"))
    return role_arn


def _read_envelopes(ctx, stream_name, shard_ids):
    """Every record on every shard from TRIM_HORIZON, gunzipped. boto3 has already undone the
    base64 framing of the wire, so ``Data`` must start with the gzip magic."""
    kinesis = ctx.client("kinesis")
    out = []
    for shard_id in shard_ids:
        it = kinesis.get_shard_iterator(StreamName=stream_name, ShardId=shard_id,
                                        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        for _ in range(20):
            resp = kinesis.get_records(ShardIterator=it, Limit=1000)
            for rec in resp["Records"]:
                blob = rec["Data"]
                assert blob[:2] == _GZIP_MAGIC, (
                    f"a subscription record must be GZIP; first bytes were {blob[:8]!r}")
                out.append(json.loads(gzip.decompress(blob)))
            it = resp.get("NextShardIterator")
            if not it or resp.get("MillisBehindLatest", 0) == 0:
                break
            time.sleep(0.25)  # 5 reads/s/shard pacing, not a wait for an effect
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
