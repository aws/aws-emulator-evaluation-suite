"""obs-s3-1-filter-4xx-alarm-fires-to-queue-quiet-filter-never-alarms."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-s3-1-filter-4xx-alarm-fires-to-queue-quiet-filter-never-alarms"
GROUP = "alerting"
SERVICES = ["cloudwatch", "s3", "sns", "sqs"]

#: Two metrics configurations on one bucket. Only the loud prefix ever sees a 4xx.
_LOUD_ID = "sim2realobsloud"
_QUIET_ID = "sim2realobsquiet"
_PREFIXES = {_LOUD_ID: "loud/", _QUIET_ID: "quiet/"}

#: Per traffic pass: successful GETs on BOTH prefixes keep both filters active (an active filter
#: publishes 4xxErrors Sum 0, which is what lets an alarm leave INSUFFICIENT_DATA for OK).
_OK_GETS_PER_PASS = 2
#: Per traffic pass once the loud alarm is OK: GETs of a missing key under loud/ only.
_MISSING_GETS_PER_PASS = 2
_THRESHOLD = 2.0
_POLL_S = 2.0
#: Traffic cadence; several passes land in every 60 s period, so a period's 404 Sum reaches the
#: threshold whatever the minute boundary.
_DRIVE_EVERY_S = 10.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _paced(fn):
    """fn, run at most once per _DRIVE_EVERY_S counted from when the pacer is made."""
    last = [time.monotonic()]

    def _call():
        if time.monotonic() - last[0] >= _DRIVE_EVERY_S:
            fn()
            last[0] = time.monotonic()

    return _call


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Real S3 404s under one FilterId drive a 4xxErrors alarm OK -> ALARM, notifying SQS via SNS.

    A twin alarm on a prefix with only successful GETs gets Sum-0 datapoints, stays OK, never fires.
    """
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    bucket = ctx.unique_name("sim2real-obs-s3-alarm-")
    create_kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # transport-only fork
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    seed_keys = {}
    for fid, prefix in _PREFIXES.items():
        s3.put_bucket_metrics_configuration(
            Bucket=bucket, Id=fid, MetricsConfiguration={"Id": fid, "Filter": {"Prefix": prefix}}
        )
        ctx.on_cleanup(
            lambda f=fid: ctx.client("s3").delete_bucket_metrics_configuration(Bucket=bucket, Id=f)
        )
        seed_keys[fid] = f"{prefix}present-object"
        s3.put_object(Bucket=bucket, Key=seed_keys[fid], Body=b"sim2real-" + fid.encode())

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-obs-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-obs-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn))

    alarms = {}
    for fid in _PREFIXES:
        name = ctx.unique_name(f"sim2real-xsvc-obs-{fid}-")
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace="AWS/S3",
            MetricName="4xxErrors",
            Dimensions=[{"Name": "BucketName", "Value": bucket},
                        {"Name": "FilterId", "Value": fid}],
            Statistic="Sum",
            Period=60,
            EvaluationPeriods=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            TreatMissingData="notBreaching",
            ActionsEnabled=True,
            AlarmActions=[topic_arn],
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda n=name: ctx.client("cloudwatch").delete_alarms(AlarmNames=[n]))
        alarms[fid] = name
    loud, quiet = alarms[_LOUD_ID], alarms[_QUIET_ID]

    quiet_states: list[str] = []
    phase = {"breaching": False}

    def _traffic() -> None:
        for fid in _PREFIXES:
            for _ in range(_OK_GETS_PER_PASS):
                s3.get_object(Bucket=bucket, Key=seed_keys[fid])["Body"].read()
        if phase["breaching"]:
            for _ in range(_MISSING_GETS_PER_PASS):
                err = _error(lambda: s3.get_object(Bucket=bucket, Key="loud/absent-key"))
                assert err == ("NoSuchKey", "The specified key does not exist."), (
                    f"missing-key GET raised {err!r}, expected "
                    f"('NoSuchKey', 'The specified key does not exist.')"
                )

    def _states() -> dict[str, str]:
        resp = cw.describe_alarms(AlarmNames=[loud, quiet], AlarmTypes=["MetricAlarm"])
        got = {a["AlarmName"]: a["StateValue"] for a in resp["MetricAlarms"]}
        quiet_states.append(got.get(quiet, "<absent>"))
        assert got.get(quiet) != "ALARM", (
            f"the control alarm {quiet!r} on FilterId {_QUIET_ID!r} entered ALARM; its prefix "
            f"{_PREFIXES[_QUIET_ID]!r} only ever received successful GETs. States so far: "
            f"{quiet_states!r}"
        )
        return got

    # notBreaching keeps a minute with no datapoint from knocking the alarm back to
    # INSUFFICIENT_DATA, so the breach below is a clean OK -> ALARM. That also means OK alone does
    # not prove the metric flows, so the barrier additionally requires real 4xxErrors datapoints
    # (Sum 0 -- an active filter publishes them) under BOTH FilterIds.
    def _phase1() -> tuple[dict, bool, bool]:
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        return (_states(), bool(_stats(cw, bucket, _LOUD_ID, "4xxErrors", since)),
                bool(_stats(cw, bucket, _QUIET_ID, "4xxErrors", since)))

    _traffic()
    _poll_until(
        _phase1,
        lambda o: o[0].get(loud) == "OK" and o[0].get(quiet) == "OK" and o[1] and o[2],
        timeout_s=_budget_s(ctx, 1500.0), interval_s=_POLL_S, ctx=ctx,
        description=(
            f"both alarms OK AND real 4xxErrors datapoints under both FilterIds (request metrics "
            f"take up to ~15 min to start after PutBucketMetricsConfiguration)"
        ),
        on_iteration=_paced(_traffic),
    )

    phase["breaching"] = True
    _traffic()
    _poll_until(
        _states, lambda s: s.get(loud) == "ALARM", timeout_s=_budget_s(ctx, 600.0),
        interval_s=_POLL_S, ctx=ctx,
        description=f"alarm {loud!r} to enter ALARM from {_MISSING_GETS_PER_PASS} 404s per pass",
        on_iteration=_paced(_traffic),
    )

    def _transitions(name: str) -> list[dict]:
        out = []
        for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=name, HistoryItemType="StateUpdate"
        ):
            for item in page["AlarmHistoryItems"]:
                data = json.loads(item["HistoryData"])
                out.append({"old": data["oldState"]["stateValue"],
                            "new": data["newState"]["stateValue"]})
        return out

    history = _poll_until(
        lambda: _transitions(loud), lambda h: {"old": "OK", "new": "ALARM"} in h,
        timeout_s=_budget_s(ctx, 180.0), interval_s=2.0, ctx=ctx,
        description=f"DescribeAlarmHistory for {loud!r} to record the OK -> ALARM StateUpdate",
    )
    assert {"old": "INSUFFICIENT_DATA", "new": "OK"} in history, (
        f"alarm {loud!r} history {history!r} lacks the INSUFFICIENT_DATA -> OK transition that "
        f"preceded the breach"
    )

    notifications: list[dict] = []

    def _drain() -> list[dict]:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            envelope = json.loads(msg["Body"])
            assert envelope.get("Type") == "Notification", f"not an SNS envelope: {envelope!r}"
            assert envelope.get("TopicArn") == topic_arn, (
                f"envelope TopicArn {envelope.get('TopicArn')!r}, expected {topic_arn!r}"
            )
            notifications.append(json.loads(envelope["Message"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return notifications

    _poll_until(
        _drain, lambda n: any(p.get("AlarmName") == loud for p in n),
        timeout_s=_budget_s(ctx, 300.0), interval_s=1.0, ctx=ctx,
        description=f"the ALARM notification for {loud!r} to arrive in the SNS-subscribed queue",
    )
    payload = next(p for p in notifications if p.get("AlarmName") == loud)
    assert payload["NewStateValue"] == "ALARM" and payload["OldStateValue"] == "OK", (
        f"notification states {payload.get('OldStateValue')!r} -> "
        f"{payload.get('NewStateValue')!r}, expected OK -> ALARM: {payload!r}"
    )
    trigger = payload["Trigger"]
    assert (trigger["Namespace"], trigger["MetricName"]) == ("AWS/S3", "4xxErrors"), (
        f"notification Trigger names {trigger.get('Namespace')!r}/{trigger.get('MetricName')!r}"
    )
    trig_dims = {d["name"]: d["value"] for d in trigger["Dimensions"]}
    assert trig_dims == {"BucketName": bucket, "FilterId": _LOUD_ID}, (
        f"notification Trigger dimensions {trig_dims!r}, expected this bucket and {_LOUD_ID!r}"
    )

    # The loud datapoint that tripped it is a real Sum >= threshold under the loud FilterId.
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    loud_peak = max(
        (float(d["Sum"]) for d in _stats(cw, bucket, _LOUD_ID, "4xxErrors", since)), default=None
    )
    assert loud_peak is not None and loud_peak >= _THRESHOLD, (
        f"4xxErrors for {_LOUD_ID!r} peaks at {loud_peak!r}, below the threshold {_THRESHOLD} "
        f"that its alarm claims was breached"
    )

    final = _states()
    assert final.get(quiet) == "OK", (
        f"control alarm {quiet!r} ended in {final.get(quiet)!r}; expected OK"
    )
    quiet_history = _transitions(quiet)
    assert all(t["new"] != "ALARM" for t in quiet_history), (
        f"control alarm {quiet!r} history records an ALARM transition: {quiet_history!r}"
    )
    assert set(quiet_states) <= {"OK", "INSUFFICIENT_DATA"}, (
        f"control alarm {quiet!r} was observed in states {quiet_states!r}"
    )
    stray = [p for p in notifications if p.get("AlarmName") != loud]
    assert stray == [], f"the queue delivered notifications for other alarms: {stray!r}"
    quiet_dps = _stats(cw, bucket, _QUIET_ID, "4xxErrors", since)
    assert quiet_dps, f"the control FilterId {_QUIET_ID!r} has no 4xxErrors datapoints at all"
    quiet_4xx = sum(float(d["Sum"]) for d in quiet_dps)
    assert quiet_4xx == 0.0, (
        f"4xxErrors for the control FilterId {_QUIET_ID!r} sums to {quiet_4xx!r}; every request "
        f"under {_PREFIXES[_QUIET_ID]!r} succeeded"
    )


def _stats(cw, bucket: str, fid: str, metric: str, since: datetime) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/S3", MetricName=metric,
        Dimensions=[{"Name": "BucketName", "Value": bucket}, {"Name": "FilterId", "Value": fid}],
        StartTime=since, EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60, Statistics=["Sum"],
    )["Datapoints"]


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call succeeded but an error was expected")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        entries = [{"Key": i["Key"], "VersionId": i["VersionId"]}
                   for g in ("Versions", "DeleteMarkers") for i in page.get(g, [])]
        if entries:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": entries}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None,
                ctx=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
