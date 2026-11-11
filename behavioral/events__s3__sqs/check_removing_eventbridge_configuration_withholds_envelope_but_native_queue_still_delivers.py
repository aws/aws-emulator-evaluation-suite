"""removing-eventbridge-configuration-withholds-envelope-but-native-queue-still-delivers."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "removing-eventbridge-configuration-withholds-envelope-but-native-queue-still-delivers"
GROUP = "event-propagation"
SERVICES = ["events", "s3", "sqs"]

#: A key exercising every encoding rule the two paths disagree on. The native S3 record carries it
#: form-encoded (space -> '+', '+' -> %2B, '=' -> %3D, UTF-8 percent-escaped, '~' -> %7E, '/' kept);
#: the EventBridge envelope carries it raw.
_KEY = "dual path/report 2026+q3=é~.txt"
_KEY_NATIVE = "dual+path/report+2026%2Bq3%3D%C3%A9%7E.txt"
_BODY = b"dual-path-subject"

_DUAL_ID = "dual-native"
_NATIVE_ONLY_ID = "native-only"
#: Real AWS routes by a cached copy of the configuration loaded at the bucket's first event, for
#: roughly five minutes (measured 294 s). The flip wait is bounded generously above that.
_FLIP_TIMEOUT_S = 480.0


# timing:real-time — ttl: 300 s
@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """One PutObject yields one native S3 record and one EventBridge envelope (raw vs form-encoded
    key); after the EventBridge configuration is removed, writes routed by the new configuration
    still reach the native queue and never produce an envelope."""
    s3 = ctx.client("s3")
    events = ctx.client("events")
    bucket = _create_bucket(ctx)
    q_native = _create_queue(ctx)
    q_events = _create_queue(ctx)
    _set_queue_policy(ctx, q_native, "s3.amazonaws.com", bucket["arn"])

    rule = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=rule,
        EventPattern=json.dumps({
            "source": ["aws.s3"],
            "detail-type": ["Object Created"],
            "detail": {"bucket": {"name": [bucket["name"]]}},
        }),
        State="ENABLED",
        Tags=_xsvc_tags_kv(),
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
    _set_queue_policy(ctx, q_events, "events.amazonaws.com", rule_arn)
    resp = events.put_targets(Rule=rule, Targets=[{"Id": "queue-e", "Arn": q_events["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["queue-e"], Force=True))
    assert resp.get("FailedEntryCount") == 0, f"PutTargets reported failures: {resp!r}"

    native_cfg = {"QueueArn": q_native["arn"], "Events": ["s3:ObjectCreated:*"]}
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "EventBridgeConfiguration": {},
            "QueueConfigurations": [{"Id": _DUAL_ID, **native_cfg}],
        },
    )
    got = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    assert "EventBridgeConfiguration" in got, (
        f"GetBucketNotificationConfiguration omits EventBridgeConfiguration after enabling it: "
        f"{ {k: v for k, v in got.items() if k != 'ResponseMetadata'}!r}"
    )

    native = _Collector(ctx, q_native["url"])
    envelopes = _Collector(ctx, q_events["url"])

    # Warm-up: S3 -> EventBridge delivery can lag the enabling call (observed once at >120 s on a
    # fresh bucket, immediate on others). Write throwaway keys until one reaches E, so the subject
    # write below is not raced against enablement. Native copies of them are ignored by key.
    warm: list = []
    warm_deadline = time.monotonic() + 360.0
    next_put = 0.0
    while time.monotonic() < warm_deadline and not any(envelopes.envelopes_for(k) for k in warm):
        if time.monotonic() >= next_put:
            warm.append(f"warmup/{len(warm):03d}.txt")
            s3.put_object(Bucket=bucket["name"], Key=warm[-1], Body=b"warm")
            next_put = time.monotonic() + 10.0
        envelopes.poll()
    assert any(envelopes.envelopes_for(k) for k in warm), (
        f"none of {len(warm)} writes over 360s produced an EventBridge envelope on E after "
        f"EventBridgeConfiguration was enabled; E saw {envelopes.summary()!r}"
    )

    # ---------------- Leg 1: one write, two families, two encodings.
    started = time.monotonic()
    put = s3.put_object(Bucket=bucket["name"], Key=_KEY, Body=_BODY)
    etag = put["ETag"].strip('"')
    deadline = time.monotonic() + 120.0
    e_latency = None
    while time.monotonic() < deadline and not (native.native_for(_KEY_NATIVE) and envelopes.envelopes_for(_KEY)):
        native.poll()
        envelopes.poll()
        if e_latency is None and envelopes.envelopes_for(_KEY):
            e_latency = time.monotonic() - started
    assert native.native_for(_KEY_NATIVE), (
        f"no native record for {_KEY_NATIVE!r} reached queue N within 120s; seen: "
        f"{native.summary()!r}"
    )
    assert envelopes.envelopes_for(_KEY), (
        f"no EventBridge envelope for raw key {_KEY!r} reached queue E within 120s; seen: "
        f"{envelopes.summary()!r}"
    )
    # Settle: keep draining briefly so a second (wrong) event on either path is caught.
    settle = time.monotonic() + 20.0
    while time.monotonic() < settle:
        native.poll()
        envelopes.poll()

    recs = native.native_for(_KEY_NATIVE)
    assert len({r["s3"]["object"].get("sequencer") for r in recs}) == 1, (
        f"queue N received {len(recs)} records for one PutObject with distinct sequencers "
        f"{sorted({r['s3']['object'].get('sequencer') for r in recs})!r}; expected one event"
    )
    rec = recs[0]
    assert rec["eventName"] == "ObjectCreated:Put", (
        f"native record eventName is {rec['eventName']!r}, expected 'ObjectCreated:Put'"
    )
    assert rec["s3"]["configurationId"] == _DUAL_ID, (
        f"native record configurationId is {rec['s3'].get('configurationId')!r}, expected {_DUAL_ID!r}"
    )
    assert rec["s3"]["object"]["key"] == _KEY_NATIVE, (
        f"native record key is {rec['s3']['object']['key']!r}; S3 records carry the key "
        f"form-encoded, expected {_KEY_NATIVE!r} for raw {_KEY!r}"
    )
    envs = envelopes.envelopes_for(_KEY)
    assert len({e["detail"]["object"].get("sequencer") for e in envs}) == 1, (
        f"queue E received {len(envs)} envelopes for one PutObject with distinct sequencers "
        f"{sorted({e['detail']['object'].get('sequencer') for e in envs})!r}; expected one event"
    )
    env = envs[0]
    assert env["source"] == "aws.s3", f"envelope source is {env['source']!r}, expected 'aws.s3'"
    assert env["detail-type"] == "Object Created", (
        f"envelope detail-type is {env['detail-type']!r}, expected 'Object Created'"
    )
    assert env["detail"]["bucket"]["name"] == bucket["name"], (
        f"envelope names bucket {env['detail']['bucket'].get('name')!r}, expected {bucket['name']!r}"
    )
    assert env["detail"]["object"]["key"] == _KEY, (
        f"envelope key is {env['detail']['object']['key']!r}; EventBridge carries the RAW key {_KEY!r}"
    )
    # Same write, two spellings: native records say `eTag`, EventBridge detail says `etag`.
    for native_field, env_field, want in (("size", "size", len(_BODY)), ("eTag", "etag", etag)):
        got_native = rec["s3"]["object"].get(native_field)
        got_env = env["detail"]["object"].get(env_field)
        assert got_native == want and got_env == want, (
            f"the two paths disagree with the write: native {native_field}={got_native!r}, "
            f"envelope {env_field}={got_env!r}, PutObject {want!r}"
        )
    assert rec["s3"]["object"]["sequencer"] == env["detail"]["object"]["sequencer"], (
        f"one write carries two sequencers: native {rec['s3']['object']['sequencer']!r}, "
        f"envelope {env['detail']['object']['sequencer']!r}"
    )
    assert env["detail"].get("reason") == "PutObject", (
        f"envelope detail.reason is {env['detail'].get('reason')!r}, expected 'PutObject'"
    )
    strays = stray_keys(envelopes, {_KEY, *warm})
    assert strays == [], f"queue E received envelopes for keys this check never wrote: {strays!r}"

    # ---------------- Leg 2: drop EventBridgeConfiguration, keep the native queue.
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={"QueueConfigurations": [{"Id": _NATIVE_ONLY_ID, **native_cfg}]},
    )
    got = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    assert "EventBridgeConfiguration" not in got, (
        f"GetBucketNotificationConfiguration still reports EventBridgeConfiguration after a "
        f"replace that omitted it: {got.get('EventBridgeConfiguration')!r}"
    )
    assert [c["Id"] for c in got.get("QueueConfigurations", [])] == [_NATIVE_ONLY_ID], (
        f"the replaced document reads back queue configurations "
        f"{[c.get('Id') for c in got.get('QueueConfigurations', [])]!r}, expected [{_NATIVE_ONLY_ID!r}]"
    )

    written: list = []
    flip_deadline = time.monotonic() + _FLIP_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < flip_deadline and not _routed_by(native, written, _NATIVE_ONLY_ID):
        if time.monotonic() >= next_put:
            key = f"after/{len(written):03d}.txt"
            s3.put_object(Bucket=bucket["name"], Key=key, Body=_BODY)
            written.append(key)
            next_put = time.monotonic() + 8.0
        native.poll()
        envelopes.poll()
    flipped = _routed_by(native, written, _NATIVE_ONLY_ID)
    assert flipped, (
        f"none of {len(written)} writes over {_FLIP_TIMEOUT_S:.0f}s was routed by the replacement "
        f"configuration {_NATIVE_ONLY_ID!r}; native routing seen: "
        f"{ {k: _ids(native, k) for k in written}!r}"
    )

    hold_s = min(max(3.0 * (e_latency or 15.0), 15.0), 120.0)
    hold_until = time.monotonic() + hold_s
    for i in range(2):
        key = f"after/{len(written):03d}.txt"
        s3.put_object(Bucket=bucket["name"], Key=key, Body=_BODY)
        written.append(key)
    while time.monotonic() < hold_until:
        native.poll()
        envelopes.poll()

    new_routed = _routed_by(native, written, _NATIVE_ONLY_ID)
    assert set(written[-2:]) <= set(new_routed), (
        f"the two writes made after the flip were not both delivered to N under {_NATIVE_ONLY_ID!r} "
        f"within {hold_s:.0f}s: {[(k, _ids(native, k)) for k in written[-2:]]!r}"
    )
    leaked = [k for k in new_routed if envelopes.envelopes_for(k)]
    assert leaked == [], (
        f"writes routed by the configuration WITHOUT EventBridgeConfiguration still produced "
        f"EventBridge envelopes on E: {leaked!r} (held {hold_s:.0f}s after the flip; leg 1 "
        f"measured E latency {e_latency!r}s)"
    )
    assert all(r["eventName"] == "ObjectCreated:Put" for k in new_routed for r in native.native_for(k)), (
        f"the surviving native path changed eventName: "
        f"{[(k, [r['eventName'] for r in native.native_for(k)]) for k in new_routed]!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_tags_kv() -> list:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK[:200]}]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")
    url = sqs.create_queue(QueueName=name, tags={_MANAGED_TAG_KEY: "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _set_queue_policy(ctx, queue: dict, service: str, source_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowServiceSend",
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sqs:SendMessage",
            "Resource": queue["arn"],
            "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
        }],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """TEARDOWN ONLY. Purge every version and delete marker, then delete the bucket."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(ctx) -> dict:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


class _Collector:
    """Accumulates everything a queue delivers: native S3 Records keyed by (encoded) key, and
    EventBridge envelopes keyed by detail.object.key. Each poll is one short receive."""

    def __init__(self, ctx, url: str):
        self._sqs = ctx.client("sqs")
        self._url = url
        self.records: dict = {}
        self.envelopes: dict = {}
        self.other: list = []

    def poll(self) -> None:
        resp = self._sqs.receive_message(QueueUrl=self._url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            self._sqs.delete_message(QueueUrl=self._url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                self.other.append(msg.get("Body", "")[:200])
                continue
            if isinstance(body, dict) and "Records" in body:
                for r in body["Records"]:
                    self.records.setdefault(r.get("s3", {}).get("object", {}).get("key"), []).append(r)
            elif isinstance(body, dict) and "detail-type" in body:
                key = (body.get("detail") or {}).get("object", {}).get("key")
                self.envelopes.setdefault(key, []).append(body)
            else:
                self.other.append(str(body)[:200])

    def native_for(self, key: str) -> list:
        return self.records.get(key, [])

    def envelopes_for(self, key: str) -> list:
        return self.envelopes.get(key, [])

    def summary(self) -> dict:
        return {"records": sorted(self.records), "envelopes": sorted(self.envelopes),
                "other": self.other[:3]}


def _ids(native: _Collector, key: str) -> list:
    return [r["s3"].get("configurationId") for r in native.native_for(key)]


def _routed_by(native: _Collector, keys: list, config_id: str) -> list:
    """Keys (raw == encoded here: [a-z0-9/._] only) whose native record names config_id."""
    return [k for k in keys if config_id in _ids(native, k)]


def stray_keys(envelopes: _Collector, expected: set) -> list:
    return sorted(k for k in envelopes.envelopes if k not in expected)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
