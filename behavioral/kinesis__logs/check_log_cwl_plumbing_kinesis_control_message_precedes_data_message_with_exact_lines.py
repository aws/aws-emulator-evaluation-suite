"""log-cwl-plumbing-kinesis-control-message-precedes-data-message-with-exact-lines."""
from __future__ import annotations

import gzip
import json
import time

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-kinesis-control-message-precedes-data-message-with-exact-lines"
GROUP = "subscription-delivery"
SERVICES = ["kinesis", "logs"]

_GZIP_MAGIC = b"\x1f\x8b"


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c6",
    "concern:data-plane",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Kinesis subscription filter puts a CONTROL_MESSAGE on the stream before any data; a later
    write arrives as a GZIP DATA_MESSAGE whose logEvents match the written lines exactly
    (messages, millisecond timestamps, and the event ids FilterLogEvents reports).
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stream_name = ctx.unique_name("sim2real-cwlp-ctl-")
    dest_arn = _create_kinesis_stream(ctx, kinesis, stream_name)
    role_arn = _make_cwl_delivery_role(ctx, [dest_arn])

    group = ctx.unique_name("sim2real-cwlp-ctl-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    log_stream = f"{group}-s"
    logs.create_log_stream(logGroupName=group, logStreamName=log_stream)

    filter_name = ctx.unique_name("sim2real-cwlp-ctl-f-")
    _put_subscription_filter(ctx, logs, group, filter_name, "", dest_arn, role_arn)

    reader = _ShardReader(kinesis, stream_name)

    # --- 1. The health-check record exists before anything was written to the group.
    controls = _poll_until(
        lambda: [r for r in reader() if r["env"]["messageType"] == "CONTROL_MESSAGE"],
        lambda rs: len(rs) >= 1,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"a CONTROL_MESSAGE record appears on {stream_name} after PutSubscriptionFilter",
    )
    for rec in controls:
        env = rec["env"]
        assert rec["raw"][:2] == _GZIP_MAGIC, (
            f"expected the control record to be gzip, first bytes {rec['raw'][:8]!r}"
        )
        assert env["owner"] == "CloudwatchLogs", (
            f"expected a CONTROL_MESSAGE owner of 'CloudwatchLogs' (the service, not the "
            f"account), got {env['owner']!r}"
        )
        assert env["logGroup"] == "" and env["logStream"] == "", (
            f"expected empty logGroup/logStream on a CONTROL_MESSAGE, got "
            f"{env['logGroup']!r}/{env['logStream']!r}"
        )
        assert env["subscriptionFilters"] == [], (
            f"expected subscriptionFilters == [] on a CONTROL_MESSAGE, got "
            f"{env['subscriptionFilters']!r}"
        )
        assert len(env["logEvents"]) == 1, (
            f"expected exactly one logEvent in a CONTROL_MESSAGE, got {env['logEvents']!r}"
        )
        msg = env["logEvents"][0]["message"]
        assert msg.startswith("CWL CONTROL MESSAGE: Checking health of destination"), (
            f"expected the documented health-check text, got {msg!r}"
        )

    # --- 2. Write three exact lines; they arrive as a DATA_MESSAGE.
    marker = ctx.unique_name("cwlp-")
    lines = [f"{marker} line-{i} payload={i * 7}" for i in range(3)]
    base = _now_ms() - 2_000
    events = [{"timestamp": base + i * 10, "message": m} for i, m in enumerate(lines)]
    resp = logs.put_log_events(logGroupName=group, logStreamName=log_stream, logEvents=events)
    assert not resp.get("rejectedLogEventsInfo"), (
        f"expected all three events accepted, got {resp.get('rejectedLogEventsInfo')!r}"
    )
    expected_ts = {e["message"]: e["timestamp"] for e in events}

    records = _poll_until(
        reader,
        lambda rs: set(lines) <= _data_messages(rs),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"all three written lines arrive as DATA_MESSAGE on {stream_name}",
    )
    data = [r for r in records if r["env"]["messageType"] == "DATA_MESSAGE"]

    # The shard's sequence order is the delivery order: the control record is first.
    first_data_seq = min(int(r["seq"]) for r in data)
    first_ctl_seq = min(int(r["seq"]) for r in controls)
    assert first_ctl_seq < first_data_seq, (
        f"expected the CONTROL_MESSAGE (seq {first_ctl_seq}) to precede the first DATA_MESSAGE "
        f"(seq {first_data_seq}) on the single shard"
    )

    source_ids = _source_event_ids(logs, group, lines)
    delivered_ids: dict[str, set[str]] = {}
    for rec in data:
        env = rec["env"]
        assert rec["raw"][:2] == _GZIP_MAGIC, (
            f"expected a gzip DATA_MESSAGE record, first bytes {rec['raw'][:8]!r}"
        )
        assert env["owner"] == account, (
            f"expected owner {account!r} (from STS), got {env['owner']!r}"
        )
        assert env["logGroup"] == group, f"expected logGroup {group!r}, got {env['logGroup']!r}"
        assert env["logStream"] == log_stream, (
            f"expected logStream {log_stream!r}, got {env['logStream']!r}"
        )
        assert env["subscriptionFilters"] == [filter_name], (
            f"expected subscriptionFilters [{filter_name!r}], got {env['subscriptionFilters']!r}"
        )
        for ev in env["logEvents"]:
            assert ev["message"] in expected_ts, (
                f"a DATA_MESSAGE carried a line that was never written: {ev['message']!r}"
            )
            assert ev["timestamp"] == expected_ts[ev["message"]], (
                f"expected timestamp {expected_ts[ev['message']]} for {ev['message']!r}, got "
                f"{ev['timestamp']!r}"
            )
            delivered_ids.setdefault(ev["message"], set()).add(ev["id"])

    for line in lines:
        assert delivered_ids.get(line) == {source_ids[line]}, (
            f"expected the delivered id for {line!r} to be the source event id "
            f"{source_ids[line]!r} reported by FilterLogEvents, got {delivered_ids.get(line)!r}"
        )


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


def _data_messages(records: list[dict]) -> set[str]:
    return {
        e["message"]
        for r in records
        if r["env"]["messageType"] == "DATA_MESSAGE"
        for e in r["env"]["logEvents"]
    }


def _source_event_ids(logs, group: str, lines: list[str]) -> dict[str, str]:
    def _read():
        out: dict[str, str] = {}
        kwargs = {"logGroupName": group}
        while True:
            page = logs.filter_log_events(**kwargs)
            for e in page.get("events", []):
                out[e["message"]] = e["eventId"]
            if not page.get("nextToken"):
                return out
            kwargs["nextToken"] = page["nextToken"]

    return _poll_until(
        _read,
        lambda ids: set(lines) <= set(ids),
        timeout_s=120.0,
        interval_s=3.0,
        description=f"FilterLogEvents reports an eventId for every line in {group}",
    )


class _ShardReader:
    """Accumulate every record on the stream's single shard, carrying the iterator forward."""

    def __init__(self, kinesis, stream_name: str) -> None:
        self._kinesis = kinesis
        shard = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]
        self._iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard["ShardId"], ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        self.records: list[dict] = []

    def __call__(self) -> list[dict]:
        for _ in range(5):
            resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=1000)
            self._iterator = resp["NextShardIterator"]
            for r in resp["Records"]:
                raw = r["Data"]
                self.records.append(
                    {"seq": r["SequenceNumber"], "raw": raw, "env": json.loads(gzip.decompress(raw))}
                )
            if resp.get("MillisBehindLatest", 0) == 0:
                break
        return list(self.records)


def _create_kinesis_stream(ctx, kinesis, name: str) -> str:
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=240.0,
        interval_s=5.0,
        description=f"Kinesis stream {name} becomes ACTIVE",
    )
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamARN"]


def _make_cwl_delivery_role(ctx, dest_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwlp-role-")
    policy_name = "cwl-to-kinesis"
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
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        finally:
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
                        "Resource": dest_arns,
                    }
                ],
            }
        ),
    )
    return role_arn


def _put_subscription_filter(ctx, logs, group, filter_name, pattern, dest_arn, role_arn) -> None:
    """Retry only while the new role's trust has not propagated (InvalidParameterException)."""

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

    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=filter_name)
    )
    _poll_until(
        _attempt,
        lambda r: r is True,
        timeout_s=180.0,
        interval_s=10.0,
        description=f"PutSubscriptionFilter accepts role {role_arn} once IAM has propagated",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
