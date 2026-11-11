"""xsvc-s3-2-eventbridge-target-without-queue-policy-dead-letters-and-counts-failures-until-fixed."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-s3-2-eventbridge-target-without-queue-policy-dead-letters-and-counts-failures-until-fixed"
GROUP = "error-propagation"
SERVICES = ["cloudwatch", "events", "s3", "sqs"]

_KEY = "incoming/subject.txt"
_BODY = b"sim2real s3 -> eventbridge -> sqs failure-path subject\n"

_DELIVERY_TIMEOUT_S = 180
_METRIC_TIMEOUT_S = 420
_FIX_TIMEOUT_S = 240


# timing:real-time — metric: 48 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """One PutObject reaches rule A's permitted queue while rule B's queue without a policy gets
    nothing: the event is dead-lettered with NO_RESOURCE and counted in B's FailedInvocations only,
    until B's queue gets the policy."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]

    bucket = _create_bucket(ctx)
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )
    eb_cfg = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in eb_cfg, (
        f"bucket {bucket!r} does not report EventBridgeConfiguration after enabling it: {eb_cfg!r}"
    )

    qa = _create_queue(ctx, "qa")
    qb = _create_queue(ctx, "qb")  # deliberately NO policy
    dlq = _create_queue(ctx, "dlq")

    pattern = json.dumps(
        {
            "source": ["aws.s3"],
            "detail-type": ["Object Created"],
            "detail": {"bucket": {"name": [bucket]}},
        }
    )
    rule_a = _create_rule(ctx, "ra", pattern)
    rule_b = _create_rule(ctx, "rb", pattern)

    _set_events_policy(sqs, qa, rule_a["arn"])
    _set_events_policy(sqs, dlq, rule_b["arn"])

    _put_target(ctx, rule_a["name"], {"Id": "a", "Arn": qa["arn"]})
    _put_target(
        ctx,
        rule_b["name"],
        {
            "Id": "b",
            "Arn": qb["arn"],
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )
    tgt_b = events.list_targets_by_rule(Rule=rule_b["name"])["Targets"]
    assert [t["Id"] for t in tgt_b] == ["b"] and tgt_b[0]["RetryPolicy"]["MaximumRetryAttempts"] == 0, (
        f"rule B's target does not read back with MaximumRetryAttempts=0: {tgt_b!r}"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    # --- PHASE 1: the PutObject. Re-sent identically only while the freshly created path is
    # going live (a brand-new rule can drop its first events and EventBridge never retries a
    # dropped event); the first write that rule A delivers is the measured one. ---
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    writes = 0
    got_a: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not got_a:
        s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY)
        writes += 1
        got_a = [m for m in _drain(ctx, qa["url"], seconds=10) if _is_subject(m["body"], bucket)]
    assert got_a, (
        f"rule A's queue (policy admits events.amazonaws.com for {rule_a['arn']!r}) received no "
        f"Object Created event for s3://{bucket}/{_KEY} after {writes} write(s) over "
        f"{_DELIVERY_TIMEOUT_S}s — the positive control for the whole S3->EventBridge->SQS path"
    )
    ev = got_a[0]["body"]
    assert ev["detail"]["object"]["size"] == len(_BODY), (
        f"rule A's event reports object size {ev['detail']['object']['size']!r}, expected {len(_BODY)}"
    )
    assert ev.get("resources") == [f"arn:{partition}:s3:::{bucket}"], (
        f"rule A's event resources are {ev.get('resources')!r}, expected exactly the bucket ARN"
    )

    # The dead letter for rule B — EventBridge's own record of why its target refused the event.
    dead = _poll(lambda: [m for m in _drain(ctx, dlq["url"], seconds=5) if _is_subject(m["body"], bucket)],
                 timeout_s=_DELIVERY_TIMEOUT_S,
                 what=f"rule B's dead-letter queue receiving the refused event for {_KEY!r}")
    attrs = {k: v.get("StringValue") for k, v in dead[0]["attributes"].items()}
    # For an SQS target whose queue has no policy admitting events.amazonaws.com, EventBridge
    # dead-letters with ERROR_CODE=NO_RESOURCE, because SQS answers the unauthorized
    # SendMessage as AWS.SimpleQueueService.NonExistentQueue ("does not exist or you do not have
    # access to it") rather than as an access denial. It is not NO_PERMISSIONS.
    assert attrs.get("ERROR_CODE") == "NO_RESOURCE", (
        f"dead letter carries ERROR_CODE={attrs.get('ERROR_CODE')!r}, expected 'NO_RESOURCE' "
        f"(all attributes: {attrs!r})"
    )
    assert "AWS.SimpleQueueService.NonExistentQueue" in (attrs.get("ERROR_MESSAGE") or ""), (
        f"dead letter ERROR_MESSAGE does not carry SQS's NonExistentQueue refusal: "
        f"{attrs.get('ERROR_MESSAGE')!r}"
    )
    assert attrs.get("TARGET_ARN") == qb["arn"], (
        f"dead letter carries TARGET_ARN={attrs.get('TARGET_ARN')!r}, expected rule B's target "
        f"{qb['arn']!r} (all attributes: {attrs!r})"
    )
    assert attrs.get("RULE_ARN") == rule_b["arn"], (
        f"dead letter carries RULE_ARN={attrs.get('RULE_ARN')!r}, expected {rule_b['arn']!r} "
        f"(all attributes: {attrs!r})"
    )
    assert dead[0]["body"]["detail"]["bucket"]["name"] == bucket, (
        f"dead-lettered body is not the S3 event for {bucket!r}: {dead[0]['body']!r}"
    )

    # The absence on B, after both A's delivery and B's dead letter have landed.
    leaked = [m for m in _drain(ctx, qb["url"], seconds=15) if _is_subject(m["body"], bucket)]
    assert leaked == [], (
        f"rule B's queue (no resource policy) received {len(leaked)} event(s): {leaked!r}"
    )
    depth = _queue_depth(sqs, qb["url"])
    assert depth == 0, f"rule B's queue reports depth {depth} behind an empty receive"

    # --- CloudWatch: the service's own record of the failure, per rule ---
    failed_b = _poll(
        lambda: [_metric_sum(ctx, "FailedInvocations", rule_b["name"], window_start)],
        timeout_s=_METRIC_TIMEOUT_S, interval_s=15,
        accept=lambda v: v[0] >= 1,
        what=f"AWS/Events FailedInvocations{{RuleName={rule_b['name']}}} reaching >= 1",
    )[0]
    assert failed_b >= 1, f"FailedInvocations for rule B summed {failed_b!r}"
    invoked_a = _poll(
        lambda: [_metric_sum(ctx, "Invocations", rule_a["name"], window_start)],
        timeout_s=_METRIC_TIMEOUT_S, interval_s=15,
        accept=lambda v: v[0] >= 1,
        what=f"AWS/Events Invocations{{RuleName={rule_a['name']}}} reaching >= 1 (metric visibility control)",
    )[0]
    assert invoked_a >= 1, f"Invocations for rule A summed {invoked_a!r}"
    failed_a = _metric_sum(ctx, "FailedInvocations", rule_a["name"], window_start)
    assert failed_a == 0, (
        f"FailedInvocations for rule A summed {failed_a!r}, expected 0 — its target was permitted "
        f"and delivered"
    )

    # --- FIX exactly one thing: B's queue gets the policy mirroring A's ---
    _set_events_policy(sqs, qb, rule_b["arn"])
    deadline = time.monotonic() + _FIX_TIMEOUT_S
    fixed_writes = 0
    got_b: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not got_b:
        s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY)
        fixed_writes += 1
        got_b = [m for m in _drain(ctx, qb["url"], seconds=15) if _is_subject(m["body"], bucket)]
    assert got_b, (
        f"after attaching the events.amazonaws.com policy (aws:SourceArn={rule_b['arn']!r}) to "
        f"rule B's queue, {fixed_writes} identical PutObject(s) over {_FIX_TIMEOUT_S}s never "
        f"reached it"
    )
    body_b = got_b[0]["body"]
    assert body_b["source"] == "aws.s3" and body_b["detail-type"] == "Object Created", (
        f"rule B's queue received {body_b.get('source')!r}/{body_b.get('detail-type')!r}, expected "
        f"aws.s3/Object Created"
    )
    assert body_b["detail"]["object"]["size"] == len(_BODY), (
        f"rule B's delivered event reports size {body_b['detail']['object']['size']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _is_subject(body: Any, bucket: str) -> bool:
    return (
        isinstance(body, dict)
        and body.get("detail-type") == "Object Created"
        and body.get("detail", {}).get("bucket", {}).get("name") == bucket
        and body.get("detail", {}).get("object", {}).get("key") == _KEY
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "b")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "xsvc-s3-2"}]}
    )
    return name


def _empty_and_delete_bucket(s3: Any, name: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(f"bucket {name}: {exc}") from exc


def _create_queue(ctx: Any, kind: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, kind)
    url = sqs.create_queue(QueueName=name, tags={"sim2real": "xsvc-s3-2"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _set_events_policy(sqs: Any, q: dict[str, str], rule_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOneEventBridgeRule",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": q["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=q["url"], Attributes={"Policy": json.dumps(policy)})


def _create_rule(ctx: Any, kind: str, pattern: str) -> dict[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, kind)
    arn = events.put_rule(
        Name=name,
        EventPattern=pattern,
        State="ENABLED",
        Description="sim2real-xsvc-s3-2",
        Tags=[{"Key": "sim2real", "Value": "xsvc-s3-2"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(events, name))
    return {"name": name, "arn": arn}


def _delete_rule(events: Any, name: str) -> None:
    ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name).get("Targets", [])]
    if ids:
        events.remove_targets(Rule=name, Ids=ids, Force=True)
    events.delete_rule(Name=name, Force=True)


def _put_target(ctx: Any, rule: str, target: dict[str, Any]) -> None:
    resp = ctx.client("events").put_targets(Rule=rule, Targets=[target])
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} failed, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _drain(ctx: Any, url: str, *, seconds: float) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        wait = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg["Body"])
            except ValueError:
                body = msg["Body"]
            out.append({"body": body, "attributes": msg.get("MessageAttributes", {})})
    return out


def _poll(probe: Any, *, timeout_s: float, what: str, interval_s: float = 0.0,
          accept: Any = bool) -> Any:
    """Bounded poll that RAISES on its deadline and never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if accept(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not observed within {timeout_s}s (last {last!r})")


def _metric_sum(ctx: Any, metric: str, rule: str, since: datetime) -> float:
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": "RuleName", "Value": rule}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(p["Sum"] for p in resp.get("Datapoints", []))


def _queue_depth(sqs: Any, url: str) -> int:
    attrs = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
