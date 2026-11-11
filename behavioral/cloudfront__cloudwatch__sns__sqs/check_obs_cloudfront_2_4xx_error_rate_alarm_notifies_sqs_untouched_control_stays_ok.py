"""obs-cloudfront-2-4xx-error-rate-alarm-notifies-sqs-untouched-control-stays-ok."""
from __future__ import annotations

import json
import time
from typing import Any

import requests

from behavioral_harness import tags

CHECK = "obs-cloudfront-2-4xx-error-rate-alarm-notifies-sqs-untouched-control-stays-ok"
GROUP = "alerting"
SERVICES = ["cloudfront", "cloudwatch", "sns", "sqs"]

#: Prefixes failures where the Deployed edge does not serve, marking them as data-plane failures.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CloudFront publishes distribution metrics only in us-east-1 (Region=Global), so the alarm, its
#: SNS topic (alarm actions are co-regional) and the subscribed queue all live there.
METRIC_REGION = "us-east-1"

#: Managed CachingDisabled policy: every viewer request reaches the origin, so nothing under test
#: is absorbed by an edge cache hit.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: Requests per 4xx burst. 4xxErrorRate is a percentage of all viewer requests in the minute, so
#: five misses beside the single 200 positive control put the minute at >= 5/6 = 83%, far above 20.
_BURST = 5
_THRESHOLD = 20.0
_PERIOD_S = 60
#: Budget for the metric -> alarm -> SNS -> SQS loop, measured from the first 4xx burst.
_ALARM_DEADLINE_S = 1200.0

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]
_XSVC_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition", ctx=None):
    """Bounded retry that raises on timeout; with ctx the deadline is capped by the run's budget."""
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _deadline(ctx, seconds) -> float:
    left = None if ctx is None else ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _deployed_etag(cf, dist_id) -> tuple[str, str]:
    r = cf.get_distribution(Id=dist_id)
    return r["Distribution"]["Status"], r["ETag"]


def _wait_deployed(cf, dist_id, *, timeout_s=1500.0, ctx=None) -> str:
    status_etag = _poll_until(lambda: _deployed_etag(cf, dist_id), lambda se: se[0] == "Deployed",
                              timeout_s=timeout_s, interval_s=2.0,
                              description=f"distribution {dist_id} to reach Deployed", ctx=ctx)
    return status_etag[1]


def _teardown_distributions(cf, dist_ids: list[str]) -> None:
    """Disable every distribution, then wait for each to deploy and delete it; raises on failure.

    DeleteDistribution is refused with DistributionNotDisabled until the disable has Deployed.
    """
    for dist_id in list(dist_ids):
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    for dist_id in list(dist_ids):
        etag = _wait_deployed(cf, dist_id)
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
        dist_ids.remove(dist_id)


def _disable_and_delete_distributions(cf, dist_ids: list[str]) -> None:
    """Backstop teardown; a failure other than not-found raises, naming the distribution ids."""
    if not dist_ids:
        return
    try:
        _teardown_distributions(cf, dist_ids)
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchDistribution",):
            raise RuntimeError(
                f"cloudfront distributions {dist_ids}: teardown failed: {exc!r}"
            ) from exc


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _create_distribution(ctx, cf, bucket, oac_id, comment) -> dict:
    return cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-xsvc-cf4xx-cr-"),
            "Comment": comment,
            "Enabled": True,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "s3origin",
                "DomainName": f"{bucket}.s3.{METRIC_REGION}.amazonaws.com",
                "S3OriginConfig": {"OriginAccessIdentity": ""},
                "OriginAccessControlId": oac_id,
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": MANAGED_CACHING_DISABLED,
            },
        },
        "Tags": {"Items": _TAG_SET},
    })["Distribution"]


def _topic_to_queue(ctx, sns, sqs, kind) -> tuple[str, str]:
    """An SNS topic with a RAW-delivery SQS subscriber, so each queue body IS the alarm JSON."""
    topic_arn = sns.create_topic(
        Name=ctx.unique_name(f"sim2real-xsvc-cf4xx-{kind}-"),
        Tags=[{"Key": k, "Value": v} for k, v in _XSVC_TAGS.items()],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-xsvc-cf4xx-{kind}-"),
                                 tags=_XSVC_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            Attributes={"RawMessageDelivery": "true"},
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return topic_arn, queue_url


def _put_4xx_alarm(ctx, cw, dist_id, topic_arn, kind) -> str:
    name = ctx.unique_name(f"sim2real-xsvc-cf4xx-{kind}-")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace="AWS/CloudFront",
        MetricName="4xxErrorRate",
        Dimensions=[{"Name": "DistributionId", "Value": dist_id},
                    {"Name": "Region", "Value": "Global"}],
        Statistic="Average",
        Period=_PERIOD_S,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        Tags=[{"Key": k, "Value": v} for k, v in _XSVC_TAGS.items()],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    return name


def _alarm(cw, name) -> dict:
    alarms = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly one alarm named {name!r}, got {alarms!r}"
    return alarms[0]


def _state_updates(cw, name) -> list[dict]:
    items: list[dict] = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=name, HistoryItemType="StateUpdate"):
        items.extend(json.loads(i["HistoryData"]) for i in page["AlarmHistoryItems"])
    return items


def _drain(sqs, queue_url) -> list[dict]:
    """One long-poll receive; returns parsed bodies and deletes what it read."""
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for m in resp.get("Messages", []):
        try:
            out.append(json.loads(m["Body"]))
        except ValueError:
            out.append({"_unparseable_body": m["Body"]})
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _get(session, url) -> Any:
    try:
        return session.get(url, timeout=15)
    except requests.RequestException as exc:  # transport only, during edge propagation
        return exc


def _fetch_ok(ctx, session, url, *, timeout_s=300.0):
    """GET url until it answers 200; exhaustion is a data-plane failure (DATAPLANE_MARKER)."""
    try:
        return _poll_until(lambda: _get(session, url),
                           lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=2.0, description=f"200 from {url}",
                           ctx=ctx)
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


def _burst_404(session, url) -> list[int]:
    codes = []
    for _ in range(_BURST):
        r = _get(session, url)
        assert isinstance(r, requests.Response), (
            f"{DATAPLANE_MARKER}: a missing-key request to the Deployed edge {url} did not get an "
            f"HTTP response at all: {r!r}"
        )
        codes.append(r.status_code)
    return codes


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1", "timing:real-time",
)
def run(ctx) -> None:
    """Real 4xx edge traffic drives a 4xxErrorRate alarm OK -> ALARM and its SNS->SQS notification;
    an identical alarm on an untouched distribution stays OK and its queue stays empty.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/monitoring-using-cloudwatch.html
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3", region=METRIC_REGION)
    cw = ctx.client("cloudwatch", region=METRIC_REGION)
    sns = ctx.client("sns", region=METRIC_REGION)
    sqs = ctx.client("sqs", region=METRIC_REGION)

    bucket = ctx.unique_name("sim2real-xsvc-cf4xx-").lower()
    s3.create_bucket(Bucket=bucket)  # us-east-1 takes no LocationConstraint
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAG_SET})
    present_key, body = "present.txt", b"sim2real-cloudfront-4xx-alarm-positive-control"
    s3.put_object(Bucket=bucket, Key=present_key, Body=body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cf4xx-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    # One net for both, registered before either create so a raise between them cannot strand one.
    dist_ids: list[str] = []
    ctx.on_cleanup(lambda: _disable_and_delete_distributions(cf, dist_ids))
    subject = _create_distribution(ctx, cf, bucket, oac_id, "sim2real 4xxErrorRate alarm subject")
    dist_ids.append(subject["Id"])

    # Cleanup is time-bounded and disable -> Deployed -> delete takes minutes, so distributions
    # are torn down here on every exit path; the net above is only a backstop.
    try:
        control = _create_distribution(ctx, cf, bucket, oac_id,
                                       "sim2real 4xxErrorRate alarm control")
        dist_ids.append(control["Id"])
        assert subject["Id"] != control["Id"], f"two creates minted one id {subject['Id']!r}"

        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowCloudFrontServicePrincipal",
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",  # deliberately NOT s3:ListBucket: a miss is then a 403
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": [subject["ARN"], control["ARN"]]}},
            }],
        }))

        # One notification path per alarm, so absence on the control side is per-queue.
        subject_topic, subject_queue = _topic_to_queue(ctx, sns, sqs, "subj")
        control_topic, control_queue = _topic_to_queue(ctx, sns, sqs, "ctrl")
        subject_alarm = _put_4xx_alarm(ctx, cw, subject["Id"], subject_topic, "subj")
        control_alarm = _put_4xx_alarm(ctx, cw, control["Id"], control_topic, "ctrl")

        _wait_deployed(cf, subject["Id"], ctx=ctx)
        _wait_deployed(cf, control["Id"], ctx=ctx)

        # Settling to OK before any traffic makes the later OK -> ALARM attributable to the traffic.
        for name in (subject_alarm, control_alarm):
            settled = _poll_until(lambda n=name: _alarm(cw, n), lambda a: a["StateValue"] == "OK",
                                  timeout_s=600.0, interval_s=2.0,
                                  description=f"alarm {name} to settle to OK on missing data",
                                  ctx=ctx)
            assert "NonBreaching" in settled["StateReason"], (
                f"alarm {name} reached OK for a reason other than missing data treated as "
                f"notBreaching: {settled['StateReason']!r}"
            )

        edge, route_headers = ctx.endpoint_route(subject["DomainName"])
        session = requests.Session()
        session.headers.update(route_headers)
        ok = _fetch_ok(ctx, session, f"{edge}/{present_key}")
        assert ok.content == body, (
            f"the edge served the wrong bytes for the present object: {ok.content[:120]!r}"
        )
        missing_url = f"{edge}/sim2real-missing-{ctx.unique_name('k-')}.txt"

        sent = 0
        next_burst = 0.0
        deadline = _deadline(ctx, _ALARM_DEADLINE_S)
        fired = None
        # One burst per alarm period, so a publication lag cannot age the datapoints out.
        while time.monotonic() < deadline:
            if time.monotonic() >= next_burst:
                codes = _burst_404(session, missing_url)
                # Without s3:ListBucket, S3 answers a missing key with AccessDenied (403).
                assert codes == [403] * _BURST, (
                    f"expected every missing-key request through the edge to answer 403, got {codes}"
                )
                sent += len(codes)
                next_burst = time.monotonic() + _PERIOD_S
            current = _alarm(cw, subject_alarm)
            if current["StateValue"] == "ALARM":
                fired = current
                break
            time.sleep(2)
        assert fired is not None, (
            f"subject alarm {subject_alarm} never reached ALARM within {_ALARM_DEADLINE_S}s of driving "
            f"{sent} 4xx viewer requests through {subject['DomainName']}; last state "
            f"{_alarm(cw, subject_alarm)['StateValue']!r}"
        )

        reason = fired["StateReason"]
        assert reason.startswith("Threshold Crossed") and "greater than the threshold (20.0)" in reason, (
            f"StateReason does not name the crossed threshold 20.0: {reason!r}"
        )
        reason_data = json.loads(fired["StateReasonData"])
        assert reason_data.get("threshold") == _THRESHOLD, (
            f"StateReasonData.threshold={reason_data.get('threshold')!r}, expected {_THRESHOLD}"
        )
        recent = reason_data.get("recentDatapoints") or []
        assert recent and all(float(v) > _THRESHOLD for v in recent), (
            f"StateReasonData.recentDatapoints {recent!r} do not all exceed {_THRESHOLD}"
        )

        history = _poll_until(
            lambda: _state_updates(cw, subject_alarm),
            lambda items: any(i["newState"]["stateValue"] == "ALARM" for i in items),
            timeout_s=180.0, interval_s=2.0,
            description=f"an ALARM StateUpdate in the history of {subject_alarm}", ctx=ctx)
        to_alarm = [i for i in history if i["newState"]["stateValue"] == "ALARM"]
        assert to_alarm[-1]["oldState"]["stateValue"] == "OK", (
            f"the first transition into ALARM came from {to_alarm[-1]['oldState']['stateValue']!r}, "
            f"expected OK (the alarm was settled to OK before any traffic): {to_alarm[-1]!r}"
        )

        received: list[dict] = []

        def notified():
            received.extend(_drain(sqs, subject_queue))
            return [m for m in received
                    if m.get("AlarmName") == subject_alarm and m.get("NewStateValue") == "ALARM"]

        hits = _poll_until(notified, bool, timeout_s=max(120.0, deadline - time.monotonic()),
                           interval_s=1.0,
                           description=f"the ALARM notification for {subject_alarm} in its SQS queue",
                           ctx=ctx)
        note = hits[0]
        assert note.get("OldStateValue") == "OK", (
            f"notification OldStateValue={note.get('OldStateValue')!r}, expected OK: {note!r}"
        )
        trigger = note.get("Trigger") or {}
        assert trigger.get("Namespace") == "AWS/CloudFront", (
            f"Trigger.Namespace={trigger.get('Namespace')!r}, expected 'AWS/CloudFront'"
        )
        assert trigger.get("MetricName") == "4xxErrorRate", (
            f"Trigger.MetricName={trigger.get('MetricName')!r}, expected '4xxErrorRate'"
        )
        dims = sorted((d.get("name"), d.get("value")) for d in trigger.get("Dimensions", []))
        assert dims == sorted([("DistributionId", subject["Id"]), ("Region", "Global")]), (
            f"Trigger.Dimensions={trigger.get('Dimensions')!r}, expected DistributionId="
            f"{subject['Id']} and Region=Global"
        )
        assert float(trigger.get("Threshold")) == _THRESHOLD, (
            f"Trigger.Threshold={trigger.get('Threshold')!r}, expected {_THRESHOLD}"
        )
        stray = [m for m in received if m.get("AlarmName") != subject_alarm]
        assert not stray, f"the subject queue received notifications for other alarms: {stray!r}"

        # Contrast: the subject's notification has arrived, so the control, evaluated on the same
        # periods with no traffic, must read OK with an empty queue and no ALARM in its history.
        control_state = _alarm(cw, control_alarm)["StateValue"]
        control_seen = _drain(sqs, control_queue)
        assert control_state == "OK", (
            f"the untouched control alarm {control_alarm} left OK while the subject alarmed: "
            f"{control_state!r}"
        )
        assert control_seen == [], (
            f"the control alarm's queue received {len(control_seen)} message(s) though its "
            f"distribution saw no traffic: {control_seen!r}"
        )
        control_alarms = [i for i in _state_updates(cw, control_alarm)
                          if i["newState"]["stateValue"] == "ALARM"]
        assert control_alarms == [], (
            f"the control alarm's history records an ALARM transition: {control_alarms!r}"
        )
    finally:
        try:
            _teardown_distributions(cf, dist_ids)
        except Exception as exc:  # noqa: BLE001 - teardown is not a fidelity verdict
            print(f"cloudfront distributions {dist_ids}: in-check teardown failed: "
                  f"{exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
