"""obs-appsync-3-4xx-error-alarm-closed-loop."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "obs-appsync-3-4xx-error-alarm-closed-loop"
GROUP = "observability"
SERVICES = ["appsync", "cloudwatch"]

NAMESPACE = "AWS/AppSync"
METRIC = "4XXError"
API_DIM = "GraphQLAPIId"
BAD_REQUESTS = 4
THRESHOLD = 3.0
METRIC_TIMEOUT_S = 600.0
ALARM_TIMEOUT_S = 300.0

SDL = """schema { query: Query }
type Query {
    ping: String
}
"""
JS_PONG = (
    "export function request(ctx) {\n  return { payload: 'pong' };\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)
APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
QUERY = {"query": "query Ping { ping }", "operationName": "Ping"}


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Four 401-rejected GraphQL requests in one minute publish AWS/AppSync 4XXError Sum 4 under the
    api's GraphQLAPIId, move a CloudWatch alarm from OK to ALARM on that datapoint, and deliver its
    SNS notification to SQS naming the metric and the api."""
    appsync = ctx.client("appsync")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    # ---- the GraphQL api: API_KEY auth, NONE data source, JS unit resolver ------------------
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-xsvc-obs-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    url = (api.get("uris") or {}).get("GRAPHQL")
    assert url, f"CreateGraphqlApi exposed no GRAPHQL uri: {api.get('uris')!r}"

    appsync.start_schema_creation(apiId=api_id, definition=SDL.encode("utf-8"))
    status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0, description="schema creation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation failed: {status['status']!r} details={status.get('details')!r}"
    )
    ds_name = ctx.unique_name("ds").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))
    appsync.create_resolver(
        apiId=api_id, typeName="Query", fieldName="ping", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_PONG,
    )
    ctx.on_cleanup(lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping"))
    key = appsync.create_api_key(apiId=api_id, description="sim2real-xsvc obs key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key))
    bad_key = "da2-" + "x" * 26
    assert bad_key != key, "the forged key collided with the real key"

    # ---- SNS topic -> SQS queue, with the queue policy that lets SNS deliver -----------------
    topic_arn, queue_url = _topic_to_queue(ctx)

    # ---- the alarm, created BEFORE any traffic so it must observe the transition ------------
    alarm = ctx.unique_name("sim2real-xsvc-obs-4xx-")
    cw.put_metric_alarm(
        AlarmName=alarm,
        AlarmDescription="sim2real-xsvc appsync 4XXError closed loop",
        Namespace=NAMESPACE, MetricName=METRIC,
        Dimensions=[{"Name": API_DIM, "Value": api_id}],
        Statistic="Sum", Period=60, EvaluationPeriods=1, Threshold=THRESHOLD,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        AlarmActions=[topic_arn],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    # Warm the endpoint with the VALID key until the resolver answers (schema + key propagation).
    _poll_until(
        lambda: _post_json(ctx, url, {"x-api-key": key}, QUERY),
        lambda res: res[0] == 200 and (res[1].get("data") or {}).get("ping") == "pong",
        timeout_s=180.0, interval_s=5.0, description="the resolver to answer on the live endpoint",
    )

    # The alarm must sit in OK before the breach, so the transition we assert is OK -> ALARM.
    _poll_until(
        lambda: _alarm(cw, alarm)["StateValue"],
        lambda s: s == "OK",
        timeout_s=ALARM_TIMEOUT_S, interval_s=10.0,
        description=f"alarm {alarm} to settle in OK before any rejected traffic",
    )

    # ---- one 60 s bucket: 4 rejected requests + 1 valid one ---------------------------------
    bucket = _fresh_minute()
    for i in range(BAD_REQUESTS):
        status_code, body = _post_json(ctx, url, {"x-api-key": bad_key}, QUERY)
        assert status_code == 401, (
            f"bad-key request {i + 1}/{BAD_REQUESTS} must be rejected with HTTP 401, got "
            f"{status_code!r} {body!r}"
        )
        errors = body.get("errors") or []
        assert errors and errors[0].get("errorType") == "UnauthorizedException", (
            f"the 401 body must name UnauthorizedException, got {body!r}"
        )
        assert "data" not in body or body.get("data") is None, (
            f"a rejected request must not execute the resolver, got data={body.get('data')!r}"
        )
    status_code, body = _post_json(ctx, url, {"x-api-key": key}, QUERY)
    assert status_code == 200 and (body.get("data") or {}).get("ping") == "pong", (
        f"the valid control request must succeed in the same minute, got {status_code!r} {body!r}"
    )
    sent_done = datetime.now(timezone.utc)
    assert sent_done < bucket + timedelta(seconds=60), (
        f"the burst spilled out of its minute bucket ({bucket.isoformat()} -> "
        f"{sent_done.isoformat()}), so the per-period Sum is no longer 4 by construction"
    )

    # ---- the metric: 4XXError Sum == 4 in that bucket, under GraphQLAPIId ------------------
    def _bucket_sum():
        pts = cw.get_metric_statistics(
            Namespace=NAMESPACE, MetricName=METRIC,
            Dimensions=[{"Name": API_DIM, "Value": api_id}],
            StartTime=bucket, EndTime=bucket + timedelta(seconds=60),
            Period=60, Statistics=["Sum"],
        ).get("Datapoints") or []
        return sum(p["Sum"] for p in pts) if pts else None

    total = _poll_until(
        _bucket_sum, lambda s: s is not None and s >= BAD_REQUESTS,
        timeout_s=METRIC_TIMEOUT_S, interval_s=15.0,
        description=f"{NAMESPACE} {METRIC} Sum for api {api_id} to reach {BAD_REQUESTS}",
    )
    assert total == float(BAD_REQUESTS), (
        f"{METRIC} must count exactly the {BAD_REQUESTS} rejected requests (the valid one adds "
        f"nothing), got Sum={total!r}"
    )

    # ---- the alarm: OK -> ALARM on the real datapoint --------------------------------------
    _poll_until(
        lambda: _alarm(cw, alarm)["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=ALARM_TIMEOUT_S, interval_s=10.0,
        description=f"alarm {alarm} to transition to ALARM",
    )

    history = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm, HistoryItemType="StateUpdate"
    ):
        history.extend(page.get("AlarmHistoryItems", []))
    to_alarm = []
    for item in history:
        data = json.loads(item.get("HistoryData") or "{}")
        if (data.get("newState") or {}).get("stateValue") == "ALARM":
            to_alarm.append(data)
    assert len(to_alarm) == 1, (
        f"expected exactly one transition into ALARM in the history, got "
        f"{[i.get('HistorySummary') for i in history]!r}"
    )
    transition = to_alarm[0]
    assert (transition.get("oldState") or {}).get("stateValue") == "OK", (
        f"the transition into ALARM must come from OK, got {transition.get('oldState')!r}"
    )
    reason = (transition.get("newState") or {}).get("stateReason") or ""
    assert "threshold" in reason.lower(), (
        f"the ALARM StateReason must describe a threshold crossing, got {reason!r}"
    )
    reason_data = (transition.get("newState") or {}).get("stateReasonData") or {}
    assert reason_data.get("recentDatapoints") == [float(BAD_REQUESTS)], (
        f"the alarm must have evaluated the real datapoint {float(BAD_REQUESTS)!r}, "
        f"stateReasonData={reason_data!r}"
    )

    # ---- the far end: the notification delivered through SNS into SQS ----------------------
    payload = _await_payload(
        sqs, queue_url,
        lambda p: p.get("AlarmName") == alarm and p.get("NewStateValue") == "ALARM",
        timeout_s=180.0, description=f"the ALARM notification for {alarm}",
    )
    trigger = payload.get("Trigger") or {}
    assert trigger.get("Namespace") == NAMESPACE, (
        f"Trigger.Namespace must be {NAMESPACE!r}, got {trigger.get('Namespace')!r}"
    )
    assert trigger.get("MetricName") == METRIC, (
        f"Trigger.MetricName must be {METRIC!r}, got {trigger.get('MetricName')!r}"
    )
    assert (API_DIM, api_id) in _dimension_pairs(trigger.get("Dimensions")), (
        f"Trigger.Dimensions must contain {API_DIM}={api_id}, got {trigger.get('Dimensions')!r}"
    )
    assert payload.get("OldStateValue") == "OK", (
        f"the notification must report the OK -> ALARM transition, got "
        f"OldStateValue={payload.get('OldStateValue')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _fresh_minute() -> datetime:
    """Block until the start of a wall-clock minute; return that minute's floor (UTC).

    Waits on the CLOCK (an observable condition), so the burst that follows lands in one
    CloudWatch 60 s bucket.
    """
    now = datetime.now(timezone.utc)
    floor = now.replace(second=0, microsecond=0)
    if now.second <= 5:
        return floor
    target = floor + timedelta(minutes=1)
    while datetime.now(timezone.utc) < target:
        time.sleep(0.5)
    return target


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _alarm(cw, name) -> dict[str, Any]:
    alarms = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(alarms) == 1, f"DescribeAlarms({name!r}) returned {len(alarms)} alarms"
    return alarms[0]


def _topic_to_queue(ctx) -> tuple[str, str]:
    """SNS topic + SQS queue subscribed to it, with the queue policy SNS needs to deliver."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-obs-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-obs-q-"), tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return topic_arn, queue_url


def _alarm_payload(raw: str) -> dict[str, Any] | None:
    """Parse one SQS body (an SNS envelope) into the CloudWatch alarm notification dict."""
    try:
        envelope = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(envelope, dict) or envelope.get("Type") != "Notification":
        return None
    try:
        payload = json.loads(envelope["Message"])
    except (KeyError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _await_payload(sqs, queue_url, predicate, *, timeout_s=180.0, description="notification"):
    """Poll SQS until an alarm payload satisfying predicate arrives; return it (raises on timeout)."""
    seen = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            payload = _alarm_payload(msg.get("Body", ""))
            if payload is None:
                continue
            seen.append(payload)
            if predicate(payload):
                return payload
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s; payloads seen: "
        f"{[(p.get('AlarmName'), p.get('NewStateValue')) for p in seen]!r}"
    )


def _dimension_pairs(raw) -> set[tuple[str, str]]:
    """Trigger.Dimensions as (name, value) pairs; the notification uses lowercase keys."""
    pairs = set()
    for d in raw if isinstance(raw, list) else []:
        if isinstance(d, dict):
            low = {str(k).lower(): v for k, v in d.items()}
            pairs.add((str(low.get("name")), str(low.get("value"))))
    return pairs


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
