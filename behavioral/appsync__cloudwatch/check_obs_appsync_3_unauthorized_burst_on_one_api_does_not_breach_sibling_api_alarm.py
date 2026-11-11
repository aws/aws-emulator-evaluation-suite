"""obs-appsync-3-unauthorized-burst-on-one-api-does-not-breach-sibling-api-alarm."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "obs-appsync-3-unauthorized-burst-on-one-api-does-not-breach-sibling-api-alarm"
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
BAD_KEY = "da2-" + "x" * 26


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:metrics",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A 401 burst on api A raises only A's 4XXError alarm: sibling api B's datapoint for that minute
    is 0 and its alarm stays OK and silent, until the same burst sent to B in a later minute
    raises B's alarm on that datapoint."""
    appsync = ctx.client("appsync")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    a_id, a_url, a_key = _graphql_api(ctx, appsync, "a")
    b_id, b_url, b_key = _graphql_api(ctx, appsync, "b")
    topic_arn, queue_url = _topic_to_queue(ctx)

    alarms = {}
    for label, api_id in (("a", a_id), ("b", b_id)):
        name = ctx.unique_name(f"sim2real-xsvc-obs-4xx-{label}-")
        cw.put_metric_alarm(
            AlarmName=name,
            AlarmDescription="sim2real-xsvc appsync 4XXError isolation",
            Namespace=NAMESPACE, MetricName=METRIC,
            Dimensions=[{"Name": API_DIM, "Value": api_id}],
            Statistic="Sum", Period=60, EvaluationPeriods=1, Threshold=THRESHOLD,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            TreatMissingData="notBreaching",
            AlarmActions=[topic_arn],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        alarms[label] = name
    alarm_a, alarm_b = alarms["a"], alarms["b"]

    for url, key, label in ((a_url, a_key, "A"), (b_url, b_key, "B")):
        _poll_until(
            lambda _u=url, _k=key: _post_json(ctx, _u, {"x-api-key": _k}, QUERY),
            lambda res: res[0] == 200 and (res[1].get("data") or {}).get("ping") == "pong",
            timeout_s=180.0, interval_s=5.0, description=f"api {label}'s resolver to answer",
        )
    for name in (alarm_a, alarm_b):
        _poll_until(
            lambda n=name: _alarm(cw, n)["StateValue"], lambda s: s == "OK",
            timeout_s=ALARM_TIMEOUT_S, interval_s=10.0,
            description=f"alarm {name} to settle in OK before any rejected traffic",
        )

    # ---- bucket 1: the burst on A only; B gets the same number of VALID requests -----------
    bucket1 = _fresh_minute()
    _burst(ctx, a_url, BAD_KEY, "A")
    for i in range(BAD_REQUESTS):
        code, body = _post_json(ctx, b_url, {"x-api-key": b_key}, QUERY)
        assert code == 200 and (body.get("data") or {}).get("ping") == "pong", (
            f"valid request {i + 1} on api B must succeed, got {code!r} {body!r}"
        )
    _within_bucket(bucket1)

    a_sum = _poll_until(
        lambda: _bucket_sum(cw, a_id, bucket1), lambda s: s is not None and s >= BAD_REQUESTS,
        timeout_s=METRIC_TIMEOUT_S, interval_s=15.0,
        description=f"api A's {METRIC} Sum to reach {BAD_REQUESTS} in bucket 1",
    )
    assert a_sum == float(BAD_REQUESTS), f"api A's {METRIC} Sum must be exactly 4, got {a_sum!r}"
    b_sum = _poll_until(
        lambda: _bucket_sum(cw, b_id, bucket1), lambda s: s is not None,
        timeout_s=METRIC_TIMEOUT_S, interval_s=15.0,
        description=f"api B's {METRIC} datapoint for bucket 1 to be published",
    )
    assert b_sum == 0.0, (
        f"api B served only valid requests, so its {METRIC} Sum for the bucket in which api A was "
        f"hit with {BAD_REQUESTS} rejections must be 0, got {b_sum!r}"
    )

    # Barrier: A's alarm fired and its notification crossed SNS -> SQS.
    _poll_until(
        lambda: _alarm(cw, alarm_a)["StateValue"], lambda s: s == "ALARM",
        timeout_s=ALARM_TIMEOUT_S, interval_s=10.0, description=f"alarm A {alarm_a} to fire",
    )
    seen: list[dict[str, Any]] = []
    _await_payload(
        sqs, queue_url, lambda p: p.get("AlarmName") == alarm_a and p.get("NewStateValue") == "ALARM",
        seen, timeout_s=180.0, description=f"alarm A's notification ({alarm_a})",
    )

    # ---- the absence: B is OK, never alarmed, never notified --------------------------------
    b_state = _alarm(cw, alarm_b)
    assert b_state["StateValue"] == "OK", (
        f"api B received no rejected request, yet its {METRIC} alarm is "
        f"{b_state['StateValue']!r}: {b_state.get('StateReason')!r}"
    )
    assert not _alarm_transitions(cw, alarm_b), (
        f"alarm B must never have entered ALARM, history shows {_alarm_transitions(cw, alarm_b)!r}"
    )
    b_notes = [p for p in seen if p.get("AlarmName") == alarm_b]
    assert not b_notes, f"api B's alarm must not notify, but the queue delivered {b_notes!r}"

    # ---- repair the one difference: the same burst, now on B, in a later bucket -------------
    bucket2 = _fresh_minute()
    assert bucket2 > bucket1, f"bucket 2 {bucket2!r} must follow bucket 1 {bucket1!r}"
    _burst(ctx, b_url, BAD_KEY, "B")
    _within_bucket(bucket2)
    _poll_until(
        lambda: _alarm(cw, alarm_b)["StateValue"], lambda s: s == "ALARM",
        timeout_s=METRIC_TIMEOUT_S, interval_s=10.0,
        description=f"alarm B {alarm_b} to fire once B itself is hit",
    )
    _await_payload(
        sqs, queue_url, lambda p: p.get("AlarmName") == alarm_b and p.get("NewStateValue") == "ALARM",
        seen, timeout_s=180.0, description=f"alarm B's notification ({alarm_b})",
    )
    transitions = _alarm_transitions(cw, alarm_b)
    assert len(transitions) == 1, f"alarm B must have entered ALARM exactly once: {transitions!r}"
    reason = (transitions[0].get("newState") or {}).get("stateReasonData") or {}
    assert reason.get("recentDatapoints") == [float(BAD_REQUESTS)], (
        f"alarm B must have breached on its own burst's datapoint, stateReasonData={reason!r}"
    )
    start = datetime.strptime(reason.get("startDate", ""), "%Y-%m-%dT%H:%M:%S.%f%z")
    assert start == bucket2, (
        f"alarm B's breaching datapoint must be bucket 2 ({bucket2.isoformat()}), never bucket 1 "
        f"({bucket1.isoformat()}); got startDate={reason.get('startDate')!r}"
    )


def _graphql_api(ctx, appsync, label) -> tuple[str, str, str]:
    """API_KEY api + ACTIVE schema + NONE data source + JS unit resolver + key -> (id, url, key)."""
    api = appsync.create_graphql_api(
        name=ctx.unique_name(f"sim2real-xsvc-obs-api-{label}-"),
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
    assert key != BAD_KEY, "the forged key collided with a real key"
    return api_id, url, key


def _burst(ctx, url, bad_key, label) -> None:
    """BAD_REQUESTS requests with a forged x-api-key; each must be an HTTP 401 Unauthorized."""
    for i in range(BAD_REQUESTS):
        code, body = _post_json(ctx, url, {"x-api-key": bad_key}, QUERY)
        assert code == 401, (
            f"bad-key request {i + 1}/{BAD_REQUESTS} on api {label} must be HTTP 401, got "
            f"{code!r} {body!r}"
        )
        errors = body.get("errors") or []
        assert errors and errors[0].get("errorType") == "UnauthorizedException", (
            f"the 401 body on api {label} must name UnauthorizedException, got {body!r}"
        )


def _within_bucket(bucket) -> None:
    done = datetime.now(timezone.utc)
    assert done < bucket + timedelta(seconds=60), (
        f"the burst spilled out of its minute bucket ({bucket.isoformat()} -> {done.isoformat()})"
    )


def _bucket_sum(cw, api_id, bucket):
    pts = cw.get_metric_statistics(
        Namespace=NAMESPACE, MetricName=METRIC,
        Dimensions=[{"Name": API_DIM, "Value": api_id}],
        StartTime=bucket, EndTime=bucket + timedelta(seconds=60),
        Period=60, Statistics=["Sum"],
    ).get("Datapoints") or []
    return sum(p["Sum"] for p in pts) if pts else None


def _alarm_transitions(cw, name) -> list[dict[str, Any]]:
    """Every StateUpdate history item whose new state is ALARM, as parsed HistoryData."""
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="StateUpdate"
    ):
        for item in page.get("AlarmHistoryItems", []):
            data = json.loads(item.get("HistoryData") or "{}")
            if (data.get("newState") or {}).get("stateValue") == "ALARM":
                out.append(data)
    return out


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


def _await_payload(sqs, queue_url, predicate, seen, *, timeout_s=180.0, description="notification"):
    """Poll SQS until a payload satisfying predicate arrives, appending EVERY payload to seen."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        matched = None
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            payload = _alarm_payload(msg.get("Body", ""))
            if payload is None:
                continue
            seen.append(payload)
            if matched is None and predicate(payload):
                matched = payload
        if matched is not None:
            return matched
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s; payloads seen: "
        f"{[(p.get('AlarmName'), p.get('NewStateValue')) for p in seen]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
