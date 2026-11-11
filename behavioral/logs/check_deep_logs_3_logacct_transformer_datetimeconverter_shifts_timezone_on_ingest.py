"""deep-logs-3-logacct-transformer-datetimeconverter-shifts-timezone-on-ingest."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-3-logacct-transformer-datetimeconverter-shifts-timezone-on-ingest"
GROUP = "transformers"
SERVICES = ["logs"]

_PREFIX = "sim2real-behav-logacct-"
_STREAM = "app"
_CONFIG = [{'parseJSON': {}},
 {'dateTimeConverter': {'source': 'ts',
                        'target': 'ts_utc',
                        'matchPatterns': ['yyyy-MM-dd HH:mm:ss'],
                        'sourceTimezone': 'America/New_York',
                        'targetTimezone': 'UTC'}}]
_RAW = ['{"ts": "2024-03-05 09:07:09", "m": "winter"}',
 '{"ts": "2024-07-05 09:07:09", "m": "summer"}']
_EXPECTED = [{'ts': '2024-03-05 09:07:09', 'm': 'winter', 'ts_utc': '2024-03-05T14:07:09.000Z'},
 {'ts': '2024-07-05 09:07:09', 'm': 'summer', 'ts_utc': '2024-07-05T13:07:09.000Z'}]
_FILTER_PATTERN = ''


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dateTimeConverter writes an America/New_York timestamp to the target field as ISO-8601 UTC with the
    zone's real offsets (+5h in March, +4h in July), leaving the source field and stored raw event unchanged.
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    stream, stream_arn, role_arn = _kinesis_sink(ctx, _PREFIX)
    group = ctx.unique_name(_PREFIX + "dtc-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK[:200]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=_STREAM)

    logs.put_transformer(logGroupIdentifier=group, transformerConfig=_CONFIG)
    ctx.on_cleanup(lambda: logs.delete_transformer(logGroupIdentifier=group))
    want = [next(iter(p)) for p in _CONFIG]
    echoed = _poll_until(
        lambda: logs.get_transformer(logGroupIdentifier=group).get("transformerConfig", []),
        lambda cfg: [next(iter(p)) for p in cfg] == want,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"GetTransformer echoes the processor chain {want!r}",
    )
    assert [next(iter(p)) for p in echoed] == want, f"GetTransformer returned {echoed!r}"

    _subscribe_transformed(ctx, logs, group, stream_arn, role_arn, _FILTER_PATTERN)
    collector = _Collector(kinesis, stream)
    base = _now_ms()
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=_STREAM,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(_RAW)],
    )
    assert not resp.get("rejectedLogEventsInfo"), f"PutLogEvents rejected events: {resp!r}"
    written_at = time.monotonic()

    def _delivered():
        collector()
        return list(dict.fromkeys(m for g, m, _ in collector.events if g == group))

    messages = _poll_until(
        _delivered,
        lambda ms: len(ms) >= len(_EXPECTED),
        timeout_s=180.0,
        interval_s=3.0,
        description=f"{len(_EXPECTED)} transformed event(s) from {group} arrive on {stream}",
    )
    latency_s = time.monotonic() - written_at
    parsed = []
    for m in messages:
        try:
            parsed.append(json.loads(m))
        except ValueError as exc:
            raise AssertionError(
                f"a subscription with applyOnTransformedLogs=true must deliver the transformed "
                f"JSON event, got non-JSON message {m!r} ({exc})"
            ) from None
    assert sorted(map(_canon, parsed)) == sorted(map(_canon, _EXPECTED)), (
        f"transformed events delivered from {group} differ from the processor's contract:\n"
        f"  got      {sorted(map(_canon, parsed))!r}\n"
        f"  expected {sorted(map(_canon, _EXPECTED))!r}"
    )

    # The transform is an added representation: the stored raw event is byte-identical.
    stored = _poll_until(
        lambda: _stored_messages(logs, group, _STREAM),
        lambda ms: len(ms) >= len(_RAW),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"GetLogEvents returns the {len(_RAW)} raw events",
    )
    assert stored == _RAW, (
        f"GetLogEvents must return the events exactly as written, not the transformed form; got "
        f"{stored!r}, expected {_RAW!r}"
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


def _until_role_usable(call):
    """Retry ``call`` while CloudWatch Logs reports it cannot yet deliver its test message to
    the destination -- the observable symptom of the new role not having propagated. Any
    other error is raised at once."""
    deadline = time.monotonic() + 180.0
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "InvalidParameterException"
                or "test message" not in err.get("Message", "")
                or time.monotonic() > deadline
            ):
                raise
        time.sleep(2)  # IAM propagation exposes no condition; the retry above is the gate


def _kinesis_sink(ctx, prefix):
    """A 1-shard Kinesis stream plus a role CloudWatch Logs can assume to write to it."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    stream = ctx.unique_name(prefix + "ks-")
    kinesis.create_stream(StreamName=stream, ShardCount=1, Tags={"sim2real": CHECK[:200]})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream, EnforceConsumerDeletion=True))
    role = ctx.unique_name(prefix + "role-")
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
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream)["StreamDescription"]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"Kinesis stream {stream} becomes ACTIVE",
    )
    stream_arn = kinesis.describe_stream(StreamName=stream)["StreamDescription"]["StreamARN"]
    iam.put_role_policy(
        RoleName=role,
        PolicyName="cwl-to-kinesis",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": stream_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName="cwl-to-kinesis"))
    return stream, stream_arn, role_arn


def _subscribe_transformed(ctx, logs, group, stream_arn, role_arn, pattern):
    """A log-group subscription filter evaluated on -- and delivering -- the TRANSFORMED event."""
    name = ctx.unique_name("sim2real-behav-logacct-sf-")
    _until_role_usable(
        lambda: logs.put_subscription_filter(
            logGroupName=group,
            filterName=name,
            filterPattern=pattern,
            destinationArn=stream_arn,
            roleArn=role_arn,
            applyOnTransformedLogs=True,
        )
    )
    ctx.on_cleanup(lambda: logs.delete_subscription_filter(logGroupName=group, filterName=name))
    return name


class _Collector:
    """Accumulate every DATA_MESSAGE event delivered to the stream as (logGroup, message,
    envelope). The shard iterator is carried forward across polls, never restarted."""

    def __init__(self, kinesis, stream: str) -> None:
        shard = kinesis.describe_stream(StreamName=stream)["StreamDescription"]["Shards"][0][
            "ShardId"
        ]
        self._kinesis = kinesis
        self._iterator = kinesis.get_shard_iterator(
            StreamName=stream, ShardId=shard, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        self.events: list[tuple[str, str, dict]] = []

    def __call__(self):
        resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=500)
        self._iterator = resp["NextShardIterator"]
        for record in resp["Records"]:
            raw = record["Data"]
            assert raw[:2] == b"\x1f\x8b", f"delivered record is not gzip: {raw[:16]!r}"
            env = json.loads(gzip.decompress(raw))
            if env.get("messageType") != "DATA_MESSAGE":
                continue
            for e in env["logEvents"]:
                self.events.append((env["logGroup"], e["message"], env))
        return list(self.events)


def _stored_messages(logs, group: str, stream: str) -> list[str]:
    out: list[str] = []
    token = None
    while True:
        kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token is not None:
            kwargs["nextToken"] = token
        page = logs.get_log_events(**kwargs)
        out.extend(e["message"] for e in page.get("events", []))
        if page.get("nextForwardToken") == token:
            return out
        token = page.get("nextForwardToken")


def _canon(d) -> str:
    return json.dumps(d, sort_keys=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
