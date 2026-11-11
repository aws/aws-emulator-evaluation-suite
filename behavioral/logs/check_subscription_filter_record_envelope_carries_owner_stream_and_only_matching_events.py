"""subscription-filter-record-envelope-carries-owner-stream-and-only-matching-events."""
from __future__ import annotations

import gzip
import json
import time

from behavioral_harness import tags

CHECK = "subscription-filter-record-envelope-carries-owner-stream-and-only-matching-events"
GROUP = "representation"
SERVICES = ["logs"]

_MATCH_TOKEN = "SIM2REALMATCH"
_GZIP_MAGIC = b"\x1f\x8b"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A subscription-delivered record is a gzip envelope naming the owner, group and origin stream,
    carrying only the events the filter matched, each with a distinct id and its exact original
    timestamp and message."""
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-logs-env-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream_a = f"{group}-stream-a"
    stream_b = f"{group}-stream-b"
    logs.create_log_stream(logGroupName=group, logStreamName=stream_a)
    logs.create_log_stream(logGroupName=group, logStreamName=stream_b)

    dest_name = ctx.unique_name("sim2real-behav-logs-env-dest-")
    dest_arn = _create_kinesis_stream(ctx, kinesis, dest_name)
    role_arn = _make_cwl_delivery_role(ctx, dest_arn)
    filter_name = ctx.unique_name("sim2real-behav-env-filter-")
    _put_subscription_filter(ctx, logs, group, filter_name, _MATCH_TOKEN, dest_arn, role_arn)

    marker = ctx.unique_name("env-")
    match_a = f"{_MATCH_TOKEN} {marker} from-stream-a"
    match_b = f"{_MATCH_TOKEN} {marker} from-stream-b"
    noise = f"quiet {marker} from-stream-a"

    collector = _RecordCollector(kinesis, _trim_horizon_iterator(kinesis, dest_name), marker)

    written_at = time.monotonic()
    ts_a = _write(logs, group, stream_a, [match_a, noise])
    ts_b = _write(logs, group, stream_b, [match_b])
    expected_ts = {**ts_a, **ts_b}

    payloads = _poll_until(
        collector,
        lambda ps: {match_a, match_b} <= _messages_in(ps),
        timeout_s=420.0,
        interval_s=10.0,
        description=(
            f"both matching events ({match_a!r} from {stream_a} and {match_b!r} from "
            f"{stream_b}) arrive on Kinesis stream {dest_name}"
        ),
    )
    latency_s = time.monotonic() - written_at

    for raw in collector.raw_blobs:
        assert raw[:2] == _GZIP_MAGIC, (
            f"expected every delivered Kinesis Data blob to be gzip (magic "
            f"{_GZIP_MAGIC!r}) after base64 decoding, got first two bytes {raw[:2]!r}"
        )

    seen_ids: list[str] = []
    for payload in payloads:
        assert payload["owner"] == account, (
            f"expected the envelope owner to be this caller's account {account!r} (read "
            f"from STS in-check), got {payload['owner']!r}"
        )
        assert payload["logGroup"] == group, (
            f"expected logGroup {group!r} in the envelope, got {payload['logGroup']!r}"
        )
        assert payload["messageType"] == "DATA_MESSAGE", (
            f"expected messageType 'DATA_MESSAGE' for a real log delivery, got "
            f"{payload['messageType']!r}"
        )
        assert payload["subscriptionFilters"] == [filter_name], (
            f"expected subscriptionFilters == [{filter_name!r}] -- the log group has exactly "
            f"one filter -- got {payload['subscriptionFilters']!r}"
        )
        messages = [e["message"] for e in payload["logEvents"]]
        expected_stream = stream_a if match_a in messages else stream_b
        assert payload["logStream"] == expected_stream, (
            f"expected logStream {expected_stream!r} for a batch carrying {messages!r}, got "
            f"{payload['logStream']!r}; a record must not attribute an event to the wrong "
            f"stream"
        )
        for event in payload["logEvents"]:
            assert isinstance(event["id"], str) and event["id"] != "", (
                f"expected every delivered event to carry a non-empty string id, got "
                f"{event['id']!r} in {payload['logStream']!r}"
            )
            seen_ids.append(event["id"])
            assert event["timestamp"] == expected_ts[event["message"]], (
                f"expected the delivered timestamp to equal the exact millisecond value "
                f"passed to PutLogEvents ({expected_ts[event['message']]}) for message "
                f"{event['message']!r}, got {event['timestamp']}"
            )

    assert len(seen_ids) == len(set(seen_ids)), (
        f"expected every delivered event id to be distinct, got {len(seen_ids)} ids with "
        f"{len(seen_ids) - len(set(seen_ids))} duplicates: {sorted(seen_ids)}"
    )

    # The hold is bounded by the measured delivery latency and re-drains throughout, so a late
    # arrival cannot slip past a single-shot read.
    hold_s = min(max(3.0 * latency_s, 15.0), 300.0)
    deadline = time.monotonic() + hold_s
    while True:
        current = _messages_in(collector())
        assert noise not in current, (
            f"expected {noise!r} to be excluded by filter pattern {_MATCH_TOKEN!r}: it was "
            f"written to {stream_a} in the same PutLogEvents batch as {match_a!r}, which was "
            f"delivered {latency_s:.0f}s later; delivered set was {sorted(current)}"
        )
        assert {match_a, match_b} <= current, (
            f"expected the two matching events to remain in the delivered set, got "
            f"{sorted(current)}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(2)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _messages_in(payloads: list[dict]) -> set[str]:
    return {e["message"] for p in payloads for e in p["logEvents"]}


class _RecordCollector:
    """Accumulate every delivered envelope mentioning ``marker`` across polls. The shard
    iterator advances with each GetRecords call and is carried forward, never restarted."""

    def __init__(self, kinesis, iterator: str, marker: str) -> None:
        self._kinesis = kinesis
        self._iterator = iterator
        self._marker = marker
        self.payloads: list[dict] = []
        self.raw_blobs: list[bytes] = []

    def __call__(self) -> list[dict]:
        resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=500)
        self._iterator = resp["NextShardIterator"]
        for record in resp["Records"]:
            raw = record["Data"]
            payload = json.loads(gzip.decompress(raw))
            if any(self._marker in e["message"] for e in payload["logEvents"]):
                self.raw_blobs.append(raw)
                self.payloads.append(payload)
        return list(self.payloads)


def _trim_horizon_iterator(kinesis, stream_name: str) -> str:
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][
        0
    ]["ShardId"]
    return kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]


def _create_kinesis_stream(ctx, kinesis, name: str) -> str:
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"Kinesis stream {name} becomes ACTIVE",
    )
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamARN"]


def _make_cwl_delivery_role(ctx, dest_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-logs-env-role-")
    policy_name = "cwl-to-destination"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": dest_arn,
                    }
                ],
            }
        ),
    )
    return role_arn


def _put_subscription_filter(ctx, logs, group, filter_name, pattern, dest_arn, role_arn) -> None:
    def _attempt():
        try:
            logs.put_subscription_filter(
                logGroupName=group,
                filterName=filter_name,
                filterPattern=pattern,
                destinationArn=dest_arn,
                roleArn=role_arn,
            )
        except logs.exceptions.InvalidParameterException as exc:
            return str(exc)
        return True

    _poll_until(
        _attempt,
        lambda r: r is True,
        timeout_s=180.0,
        interval_s=10.0,
        description=(
            f"PutSubscriptionFilter accepts role {role_arn} for {group} once the IAM trust "
            f"policy has propagated"
        ),
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=filter_name)
    )


def _write(logs, group: str, stream: str, messages: list[str]) -> dict[str, int]:
    """Write messages to one stream and return the exact millisecond timestamp used per
    message, so the delivered envelope can be checked against it."""
    base = _now_ms()
    events = [{"timestamp": base + i, "message": m} for i, m in enumerate(messages)]
    resp = logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        f"expected {len(messages)} in-window events accepted for {stream}, got "
        f"rejectedLogEventsInfo {rejected!r}"
    )
    return {e["message"]: e["timestamp"] for e in events}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
