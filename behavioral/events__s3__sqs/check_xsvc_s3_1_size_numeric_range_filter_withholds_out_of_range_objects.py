"""xsvc-s3-1-size-numeric-range-filter-withholds-out-of-range-objects."""
from __future__ import annotations

import copy
import json
import time

from behavioral_harness import tags

CHECK = "xsvc-s3-1-size-numeric-range-filter-withholds-out-of-range-objects"
GROUP = "event-propagation"
SERVICES = ["events", "s3", "sqs"]

#: The content filter under test, applied to `detail.object` of an S3 "Object Created" event:
#: a half-open byte range [100, 200).
_OBJECT_FILTER = {"size": [{"numeric": [">=", 100, "<", 200]}]}
#: Matching object put FIRST, before anything is asserted: its arrival on BOTH queues proves both
#: rules are live, so a later absence cannot be blamed on a rule that had not propagated yet.
#: A freshly created rule/target can silently drop its very first delivered event
#: (PutRule/PutTargets return before the subscription path is fully live), so the
#: warm-up retries with a FRESH key per attempt rather than a fixed one.


def _warmup_key(attempt: int) -> tuple[str, int]:
    return (f"warmup-{attempt}.bin", 150)
#: One byte outside each bound.
_NEAR_MISSES = [
    ("below-lower.bin", 99),
    ("at-upper.bin", 200),
]
#: Put AFTER the near-misses on the same bucket and the same rule: both inclusive edges.
_CONTROLS = [
    ("at-lower.bin", 100),
    ("below-upper.bin", 199),
]

_DELIVERY_BUDGET_S = 180.0
# The slowest positive delivery this check calibrates an absence window against.
_MAX_CREDIBLE_DELIVERY_WAIT_S = 180.0
_ABSENCE_FLOOR_BUDGET_S = 30.0
_ABSENCE_CEILING_BUDGET_S = 90.0


# The mailbox keeps EVERY body it drains so that waiting for one key never discards another key's
# evidence.
class _Mailbox:
    def __init__(self, sqs, url: str, label: str):
        self.sqs, self.url, self.label = sqs, url, label
        self.bodies: list[str] = []

    def _pull(self, wait: int) -> None:
        resp = self.sqs.receive_message(
            QueueUrl=self.url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        msgs = resp.get("Messages", [])
        if msgs:
            self.sqs.delete_message_batch(QueueUrl=self.url, Entries=[
                {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]}
                for i, m in enumerate(msgs)])
        self.bodies += [m["Body"] for m in msgs]

    def envelopes(self) -> list[dict]:
        return [json.loads(b) for b in self.bodies]

    def keys(self) -> set[str]:
        return {e["detail"]["object"]["key"] for e in self.envelopes()}

    def poll_keys(self, wanted: set[str], budget_s: float) -> float | None:
        """Seconds until every wanted key has arrived, or None if budget_s runs out first."""
        started = time.monotonic()
        deadline = started + budget_s
        while not wanted <= self.keys():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._pull(max(1, min(5, int(remaining))))
        return time.monotonic() - started

    def soak(self, budget_s: float) -> None:
        deadline = time.monotonic() + budget_s
        while (remaining := deadline - time.monotonic()) > 0:
            self._pull(max(1, min(5, int(remaining))))

    def depth(self, ctx) -> dict:
        return _wait_counters_zero(
            ctx, self.sqs, self.url,
            ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes).
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s counter wait ended (last={attrs!r}); not graded"
                )
            return attrs
        time.sleep(interval_s)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        items = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                 for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if items:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": items, "Quiet": True}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-xsvc-s3f-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _make_queue(ctx, sqs, account: str) -> tuple[str, str]:
    """A queue whose policy admits default-bus rules; S3 service events land on the DEFAULT bus."""
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-s3f-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridge", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnLike": {
                "aws:SourceArn": f"arn:aws:events:{ctx.region}:{account}:rule/*"}},
        }],
    })})
    return url, arn


def _make_rule(ctx, ev, pattern: dict, queue_arn: str) -> str:
    rule = ctx.unique_name("sim2real-xsvc-s3f-")
    ev.put_rule(Name=rule, State="ENABLED", EventPattern=json.dumps(pattern),
                Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))
    resp = ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, (
        f"put_targets on {rule!r} reported failures: {resp.get('FailedEntries')!r}")
    stored = json.loads(ev.describe_rule(Name=rule)["EventPattern"])
    assert stored == pattern, (
        f"DescribeRule must return the pattern as written; wrote {pattern!r}, got {stored!r}")
    return rule


def _filter_scenario(ctx, object_filter, warmup_key_fn, near_misses, controls) -> None:
    ev, s3, sqs = ctx.client("events"), ctx.client("s3"), ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _make_bucket(ctx, s3)
    filt_url, filt_arn = _make_queue(ctx, sqs, account)
    obs_url, obs_arn = _make_queue(ctx, sqs, account)

    base = {"source": ["aws.s3"], "detail-type": ["Object Created"],
            "detail": {"bucket": {"name": [bucket]}}}
    filtered = copy.deepcopy(base)
    filtered["detail"]["object"] = object_filter
    _make_rule(ctx, ev, filtered, filt_arn)
    _make_rule(ctx, ev, base, obs_arn)

    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}})
    enabled = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in enabled, (
        f"bucket must be wired to EventBridge; GetBucketNotificationConfiguration -> {enabled!r}")

    filt = _Mailbox(sqs, filt_url, "filtered-rule queue")
    obs = _Mailbox(sqs, obs_url, "unfiltered observer queue")

    def put(key: str, size: int) -> None:
        s3.put_object(Bucket=bucket, Key=key, Body=b"x" * size)

    # --- warm-up: one matching object must reach BOTH rules before the trial starts ----------
    # Retried with a fresh key per attempt: a freshly created rule/target can silently drop its
    # first delivered event, and EventBridge never retries a dropped one.
    warm_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    attempt = 0
    warmup_key = warmup_size = warm_latency = None
    # Every attempt is tracked, not just the one that is confirmed first: an earlier attempt's
    # event may have been dropped or merely SLOW, so it may or may not land later. It matches the
    # filter under test either way, so the exact-set assertions below tolerate it without
    # requiring it.
    attempted_warmups: list[tuple[str, int]] = []
    while warmup_key is None:
        attempt += 1
        key, size = warmup_key_fn(attempt)
        attempted_warmups.append((key, size))
        put(key, size)
        remaining = warm_deadline - time.monotonic()
        assert remaining > 0, f"warm-up key never delivered after {attempt} attempts"
        window = min(30.0, remaining)
        filt_lat = filt.poll_keys({key}, window)
        obs_lat = obs.poll_keys({key}, window) if filt_lat is not None else None
        if obs_lat is None:
            continue
        warmup_key, warmup_size, warm_latency = key, size, max(filt_lat, obs_lat)

    # --- trial: near-misses first, then the matching control, same bucket, same rule ----------
    for key, size in near_misses:
        put(key, size)
    for key, size in controls:
        put(key, size)
    control_keys = {k for k, _ in controls}
    miss_keys = {k for k, _ in near_misses}
    control_sizes = dict(controls)
    miss_sizes = dict(near_misses)
    # Retried: delivery can be dropped even to an already-warmed target (not only a brand-new
    # one's FIRST event), so a timed-out wait re-puts whichever keys are still missing -- an
    # idempotent overwrite that fires a fresh S3 event -- rather than trusting a single wait.
    trial_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    trial_latency = None
    while trial_latency is None:
        remaining = trial_deadline - time.monotonic()
        assert remaining > 0, (
            f"control keys {sorted(control_keys - filt.keys())!r} never delivered after retries")
        trial_latency = filt.poll_keys(control_keys, min(60.0, remaining))
        if trial_latency is None:
            for k in sorted(control_keys - filt.keys()):
                put(k, control_sizes[k])

    # The observer has no content filter, so it must see every near-miss: that proves S3
    # EMITTED each one and the bus delivered it over identical wiring. Retried the same way.
    obs_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    obs_done = False
    while not obs_done:
        remaining = obs_deadline - time.monotonic()
        assert remaining > 0, (
            f"observer missing {sorted((miss_keys | control_keys) - obs.keys())!r} after retries")
        obs_done = obs.poll_keys(miss_keys | control_keys, min(60.0, remaining)) is not None
        if not obs_done:
            for k in sorted((miss_keys | control_keys) - obs.keys()):
                size = control_sizes.get(k, miss_sizes.get(k))
                put(k, size)

    measured = max(warm_latency, trial_latency)
    assert measured <= _MAX_CREDIBLE_DELIVERY_WAIT_S, (
        f"slowest positive delivery took {measured:.1f}s, above the "
        f"{_MAX_CREDIBLE_DELIVERY_WAIT_S}s this check will calibrate an absence against")
    window = min(max(_ABSENCE_FLOOR_BUDGET_S, 3.0 * measured), _ABSENCE_CEILING_BUDGET_S)
    filt.soak(window)

    leaked = sorted(filt.keys() & miss_keys)
    assert leaked == [], (
        f"filter {object_filter!r} must withhold the near-miss keys, but the filtered queue "
        f"received {leaked!r} within {window:.0f}s (the observer received all of "
        f"{sorted(miss_keys)!r}, and the same rule delivered the control {sorted(control_keys)!r})")
    unconfirmed = {k for k, _ in attempted_warmups} - {warmup_key}
    expected = control_keys | {warmup_key}
    assert filt.keys() - unconfirmed == expected, (
        f"filtered queue must hold exactly the matching keys {sorted(expected)!r} (plus any of "
        f"the unconfirmed warm-ups {sorted(unconfirmed)!r}); got {sorted(filt.keys())!r}")
    assert obs.keys() - unconfirmed == expected | miss_keys, (
        f"observer must hold every key put; expected {sorted(expected | miss_keys)!r}, "
        f"got {sorted(obs.keys())!r}")

    sizes = dict([*attempted_warmups, *near_misses, *controls])
    for env in filt.envelopes():
        key = env["detail"]["object"]["key"]
        assert env["source"] == "aws.s3", f"source must be 'aws.s3', got {env['source']!r}"
        assert env["detail-type"] == "Object Created", (
            f"detail-type must be 'Object Created', got {env['detail-type']!r}")
        assert env["detail"]["bucket"]["name"] == bucket, (
            f"detail.bucket.name must be {bucket!r}, got {env['detail']['bucket']['name']!r}")
        assert env["detail"]["object"]["size"] == sizes[key], (
            f"detail.object.size for {key!r} must be {sizes[key]!r}, "
            f"got {env['detail']['object']['size']!r}")
    depth = filt.depth(ctx)
    assert depth == {"ApproximateNumberOfMessages": "0",
                     "ApproximateNumberOfMessagesNotVisible": "0"}, (
        f"filtered queue must be empty after the soak; attributes {depth!r}")


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge `numeric` filter on `detail.object.size` delivers exactly the S3 objects of
    100 and 199 bytes for the range [100, 200) and withholds the 99- and 200-byte objects that an
    unfiltered observer rule receives, each envelope carrying the size put."""
    # Pattern operators: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
    _filter_scenario(ctx, _OBJECT_FILTER, _warmup_key, _NEAR_MISSES, _CONTROLS)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
