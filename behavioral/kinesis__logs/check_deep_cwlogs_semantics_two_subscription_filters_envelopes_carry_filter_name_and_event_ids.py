"""deep-cwlogs-semantics-two-subscription-filters-envelopes-carry-filter-name-and-event-ids."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-two-subscription-filters-envelopes-carry-filter-name-and-event-ids"
GROUP = "subscription-delivery"
SERVICES = ["kinesis", "logs"]

_GZIP_MAGIC = b"\x1f\x8b"
_DELIVERY_BUDGET_S = 200.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two filters on one log group to one stream each deliver envelopes naming only that filter
    with only its matches; a shared match goes to both, delivered ids equal FilterLogEvents
    eventIds, and events written before the filters or matching neither are never delivered.
    """
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    stream_name, stream_arn = _create_active_stream(ctx)
    shard_ids = [s["ShardId"] for s in ctx.client("kinesis").list_shards(StreamName=stream_name)["Shards"]]
    role_arn = _create_logs_delivery_role(ctx, stream_arn)

    group = ctx.unique_name("sim2real-xsvc-lg-twosub-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    log_stream = "app"
    logs.create_log_stream(logGroupName=group, logStreamName=log_stream)

    # Written before any subscription exists: must never be delivered.
    _put(logs, group, log_stream, ["alpha written-before-subscription", "beta written-before-subscription"])

    filters = {"alpha": ctx.unique_name("sim2real-xsvc-sf-alpha-"),
               "beta": ctx.unique_name("sim2real-xsvc-sf-beta-")}
    for term, name in filters.items():
        _retry_invalid_parameter(
            lambda _n=name, _t=term: logs.put_subscription_filter(
                logGroupName=group, filterName=_n, filterPattern=_t,
                destinationArn=stream_arn, roleArn=role_arn),
            timeout_s=120.0,
            description=f"PutSubscriptionFilter {name} once the delivery role has propagated",
        )
        ctx.on_cleanup(lambda _n=name: logs.delete_subscription_filter(logGroupName=group, filterName=_n))

    live = ["alpha one", "beta one", "alpha beta both", "gamma neither", "alpha two"]
    _put(logs, group, log_stream, live)
    expected = {
        filters["alpha"]: {"alpha one", "alpha beta both", "alpha two"},
        filters["beta"]: {"beta one", "alpha beta both"},
    }

    def _delivered():
        by_filter = {name: {} for name in expected}
        for env in _read_envelopes(ctx, stream_name, shard_ids):
            if env["messageType"] != "DATA_MESSAGE":
                continue
            assert env["owner"] == account and env["logGroup"] == group and env["logStream"] == log_stream, (
                f"envelope header must name owner={account!r}, logGroup={group!r}, "
                f"logStream={log_stream!r}; got {({k: env.get(k) for k in ('owner', 'logGroup', 'logStream')})!r}"
            )
            assert len(env["subscriptionFilters"]) == 1 and env["subscriptionFilters"][0] in by_filter, (
                f"each envelope must name exactly one of {sorted(by_filter)!r} in subscriptionFilters; "
                f"got {env['subscriptionFilters']!r}"
            )
            for ev in env["logEvents"]:
                by_filter[env["subscriptionFilters"][0]][ev["message"]] = (ev["id"], ev["timestamp"])
        return by_filter

    delivered = _poll_until(
        _delivered,
        lambda d: all(expected[n] <= set(d[n]) for n in expected),
        timeout_s=_DELIVERY_BUDGET_S, interval_s=10.0,
        description="both filters' matching events to be delivered to Kinesis",
    )
    for name, want in expected.items():
        assert set(delivered[name]) == want, (
            f"filter {name!r} must deliver exactly {sorted(want)!r} (its matches written after it "
            f"existed); delivered {sorted(delivered[name])!r}"
        )

    stored = {}
    for page in logs.get_paginator("filter_log_events").paginate(logGroupName=group):
        for ev in page["events"]:
            stored[ev["message"]] = (ev["eventId"], ev["timestamp"])
    for name in expected:
        for message, delivered_ref in delivered[name].items():
            assert stored.get(message) == delivered_ref, (
                f"event {message!r} was delivered by {name!r} as (id, timestamp)={delivered_ref!r} "
                f"but FilterLogEvents reports {stored.get(message)!r}; the delivered id must be the "
                "stored event's eventId"
            )


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
