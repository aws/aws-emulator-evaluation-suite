"""xsvc-apigateway-1-stage-500-is-retried-then-dead-lettered-with-error-code."""
from __future__ import annotations

import datetime
import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-1-stage-500-is-retried-then-dead-lettered-with-error-code"
GROUP = "error-propagation"
SERVICES = ["apigateway", "events", "iam", "sqs"]

_SOURCE = "sim2real.orders"
_DETAIL_TYPE = "OrderPlaced"
_RETRIES = 2


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "concern:metrics",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """An EventBridge target whose REST stage answers 500 is retried (>= 1 + MaximumRetryAttempts
    requests), dead-lettered with ERROR_CODE/RULE_ARN/TARGET_ARN and counted in FailedInvocations,
    while a control rule on the same event targeting a 200 route leaves its DLQ empty."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    sink_url, sink_arn, sink_name = _queue(ctx, "sim2real-xsvc-apigw1-sink-")
    api_id, stage = _rest_api_to_queue(ctx, account, sink_name, sink_arn,
                                       routes={"orders": "500", "accepted": "200"})
    warm = ctx.unique_name("warm-")
    _poll_signed_post(ctx, _stage_url(ctx, api_id, stage, "accepted/w-1"),
                      {"marker": warm}, {}, expected=200)
    _collect(sqs, sink_url, lambda m: _marker_of(m) == warm, want=1, timeout_s=60)
    probe = ctx.unique_name("probe-")
    status, body = _signed_post(ctx, _stage_url(ctx, api_id, stage, "orders/w-2"),
                                {"marker": probe}, {})
    assert (status, json.loads(body)) == (500, {"stage_status": 500}), (
        f"the failing route answered {status!r} {body!r}, expected 500 {{'stage_status': 500}}"
    )
    rec = _collect(sqs, sink_url, lambda m: _marker_of(m) == probe, want=1, timeout_s=60)
    assert _attr(rec[0], "route") == "/orders/{id}", f"probe recorded {_attr(rec[0], 'route')!r}"

    pattern = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}
    bus, ok_rule, ok_rule_arn = _bus_and_rule(ctx, pattern)
    stage_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/{stage}"
    role_arn = _role(ctx, "sim2real-xsvc-apigw1-evb-", "events.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke",
                       "Resource": f"{stage_arn}/POST/*"}],
    })
    ok_target = {"Id": "ok", "Arn": f"{stage_arn}/POST/accepted/*", "RoleArn": role_arn,
                 "HttpParameters": {"PathParameterValues": ["$.detail.id"]}}
    _put_target(ctx, bus, ok_rule, ok_target)

    def _entry(marker):
        return {"EventBusName": bus, "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"id": f"ord-{marker[-6:]}", "marker": marker})}

    sent: dict[str, dict] = {}

    def _publish():
        marker = ctx.unique_name("ctl-")
        r = events.put_events(Entries=[_entry(marker)])
        assert r["FailedEntryCount"] == 0, f"put_events rejected the entry: {r!r}"
        sent[marker] = {}

    # Warm the EventBridge role on the control path only, before any DLQ exists.
    _deliver_with_retry(sqs, sink_url, _publish, sent, attempt_s=25, total_s=180)

    ok_dlq_url, ok_dlq_arn = _dlq_for_rule(ctx, "sim2real-xsvc-apigw1-okdlq-", ok_rule_arn)
    ok_target = {**ok_target, "DeadLetterConfig": {"Arn": ok_dlq_arn},
                 "RetryPolicy": {"MaximumRetryAttempts": _RETRIES,
                                 "MaximumEventAgeInSeconds": 3600}}
    _put_target(ctx, bus, ok_rule, ok_target)

    _, bad_rule, bad_rule_arn = _bus_and_rule(ctx, pattern, bus=bus)
    bad_dlq_url, bad_dlq_arn = _dlq_for_rule(ctx, "sim2real-xsvc-apigw1-baddlq-", bad_rule_arn)
    bad_target_arn = f"{stage_arn}/POST/orders/*"
    _put_target(ctx, bus, bad_rule, {
        "Id": "failing", "Arn": bad_target_arn, "RoleArn": role_arn,
        "HttpParameters": {"PathParameterValues": ["$.detail.id"]},
        "DeadLetterConfig": {"Arn": bad_dlq_arn},
        "RetryPolicy": {"MaximumRetryAttempts": _RETRIES, "MaximumEventAgeInSeconds": 3600},
    })

    # A rule created seconds ago may not match yet (a new failing rule can record
    # InvocationAttempts=0 while an older control rule delivers). Re-publish, bounded, until
    # the failing route records a first attempt; that event is the one graded. Every candidate
    # reaches the failing rule only if it matched, so the rule's metrics stay specific to it.
    started = datetime.datetime.now(datetime.timezone.utc)
    candidates: dict[str, tuple[float, str]] = {}
    sink_seen: list = []
    marker = None
    live_deadline = time.monotonic() + 180
    while marker is None and time.monotonic() < live_deadline:
        cand = ctx.unique_name("evt-")
        t_pub = time.monotonic()
        r = events.put_events(Entries=[_entry(cand)])
        assert r["FailedEntryCount"] == 0, f"put_events rejected the entry: {r!r}"
        candidates[cand] = (t_pub, r["Entries"][0]["EventId"])
        until = time.monotonic() + 30
        while marker is None and time.monotonic() < until:
            for m in _drain_for(sqs, sink_url, 2):
                sink_seen.append(m)
                if _marker_of(m) in candidates and _attr(m, "route") == "/orders/{id}":
                    marker = marker or _marker_of(m)
    assert marker is not None, (
        f"the failing rule never invoked the stage for any of {len(candidates)} events in 180s")
    t0, event_id = candidates[marker]

    ok_hits = [m for m in sink_seen
               if _marker_of(m) == marker and _attr(m, "route") == "/accepted/{id}"]
    if not ok_hits:
        ok_hits = _collect(sqs, sink_url, lambda m: _marker_of(m) == marker
                           and _attr(m, "route") == "/accepted/{id}", want=1, timeout_s=60,
                           seen=sink_seen)
    ok_latency = time.monotonic() - t0
    assert _attr(ok_hits[0], "pathId") == f"ord-{marker[-6:]}", (
        f"control delivery carried path id {_attr(ok_hits[0], 'pathId')!r}")

    # Wait for the dead letter while draining the stage's sink, so the attempt timeline is
    # part of any failure message. Dead-lettering can take ~3.5 minutes after PutEvents.
    timeline = [("before-wait", _attr(m, "route")) for m in sink_seen if _marker_of(m) == marker]
    dead = None
    deadline = time.monotonic() + 540
    while dead is None and time.monotonic() < deadline:
        for m in _drain_for(sqs, sink_url, 1):
            sink_seen.append(m)
            if _marker_of(m) == marker:
                timeline.append((round(time.monotonic() - t0, 1), _attr(m, "route")))
        got = sqs.receive_message(QueueUrl=bad_dlq_url, MaxNumberOfMessages=10,
                                  WaitTimeSeconds=5, MessageAttributeNames=["All"])
        for m in got.get("Messages", []):
            sqs.delete_message(QueueUrl=bad_dlq_url, ReceiptHandle=m["ReceiptHandle"])
            if _marker_of(m) == marker:
                dead = m
    if dead is None:
        raise AssertionError(
            f"the failing target never dead-lettered the event in 540s; stage attempts "
            f"(s, route): {timeline!r}; rule metrics: "
            f"{_rule_metrics(cw, bad_rule, bus, started)!r}")
    attrs = {k: v.get("StringValue") for k, v in dead.get("MessageAttributes", {}).items()}
    assert attrs.get("RULE_ARN") == bad_rule_arn, f"DLQ RULE_ARN {attrs.get('RULE_ARN')!r}"
    assert attrs.get("TARGET_ARN") == bad_target_arn, (
        f"DLQ TARGET_ARN {attrs.get('TARGET_ARN')!r}, expected {bad_target_arn!r}")
    # A 5xx from the stage is classified CONNECTION_FAILURE, and the
    # message quotes the status and the substituted request line.
    assert attrs.get("ERROR_CODE") == "CONNECTION_FAILURE", (
        f"DLQ ERROR_CODE {attrs.get('ERROR_CODE')!r}; all attributes {attrs!r}")
    expected_line = (f'Got status code "500" while trying to invoke "POST '
                     f'{ctx.api_url(api_id, stage)}/orders/ord-{marker[-6:]}"')
    # message varies: AWS appends the Request ID of its own call to the stage, minted per
    # delivery attempt; every other byte of the message is asserted.
    message = attrs.get("ERROR_MESSAGE") or ""
    request_id = message.rpartition("; Request ID: ")[2].partition(";")[0]
    expected_message = (f"{expected_line}. (Service: api_gateway; Status Code: 500; "
                        f"Error Code: Internal Server Error; Request ID: {request_id}; Proxy: null)")
    assert message == expected_message, (
        f"DLQ ERROR_MESSAGE {message!r} != {expected_message!r}")
    assert (attrs.get("RETRY_ATTEMPTS"), attrs.get("EXHAUSTED_RETRY_CONDITION")) == (
        str(_RETRIES), "MaximumRetryAttempts"), (
        f"DLQ says RETRY_ATTEMPTS={attrs.get('RETRY_ATTEMPTS')!r} exhausted by "
        f"{attrs.get('EXHAUSTED_RETRY_CONDITION')!r}, expected {_RETRIES} / MaximumRetryAttempts")
    dead_event = json.loads(dead["Body"])
    assert dead_event.get("id") == event_id, (
        f"dead-lettered event id {dead_event.get('id')!r} != PutEvents EventId {event_id!r}")

    # Every attempt was written by the stage before it answered 500; by the time the event is
    # dead-lettered all 1 + MaximumRetryAttempts attempts have happened. A floor, not an exact
    # count: 3 and 7 requests have been seen for RETRY_ATTEMPTS=2, because one attempt may
    # itself re-send.
    sink_seen += _drain_for(sqs, sink_url, max(10.0, 3 * ok_latency))
    attempts = [m for m in sink_seen
                if _marker_of(m) == marker and _attr(m, "route") == "/orders/{id}"]
    assert len(attempts) >= 1 + _RETRIES, (
        f"the 500 route recorded {len(attempts)} attempts for the event; RetryPolicy "
        f"MaximumRetryAttempts={_RETRIES} requires {1 + _RETRIES} before dead-lettering"
    )

    ok_dead = [m for m in _drain_for(sqs, ok_dlq_url, max(10.0, 3 * ok_latency))
               if _marker_of(m) in candidates]
    assert not ok_dead, f"the 200 control target dead-lettered the event: {ok_dead!r}"

    _assert_failed_invocations(cw, bad_rule, bus, started)


def _rule_metrics(cw, rule, bus, started):
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)
    out = {}
    for name in ("InvocationAttempts", "RetryInvocationAttempts", "FailedInvocations",
                 "DeadLetterInvocations", "InvocationsFailedToBeSentToDlq"):
        pts = cw.get_metric_statistics(
            Namespace="AWS/Events", MetricName=name,
            Dimensions=[{"Name": "EventBusName", "Value": bus},
                        {"Name": "RuleName", "Value": rule}],
            StartTime=started - datetime.timedelta(minutes=5), EndTime=end,
            Period=60, Statistics=["Sum"],
        )["Datapoints"]
        out[name] = sum(d["Sum"] for d in pts)
    return out


def _assert_failed_invocations(cw, rule, bus, started, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)
        # A rule on a CUSTOM bus publishes under the EventBusName+RuleName dimension
        # set; RuleName alone returns no datapoints for it.
        resp = cw.get_metric_statistics(
            Namespace="AWS/Events", MetricName="FailedInvocations",
            Dimensions=[{"Name": "EventBusName", "Value": bus},
                        {"Name": "RuleName", "Value": rule}],
            StartTime=started - datetime.timedelta(minutes=5), EndTime=end,
            Period=60, Statistics=["Sum"],
        )
        last = resp["Datapoints"]
        if sum(d["Sum"] for d in last) >= 1:
            return
        time.sleep(10)
    raise AssertionError(f"AWS/Events FailedInvocations for {rule!r} never reached 1 within "
                         f"{timeout_s}s; datapoints {last!r}")


# REST API (AWS_IAM POST /<route>/{id}) whose AWS-type integration calls SQS SendMessage on a sink
# queue, recording the received body verbatim plus the path id, the x-order-src header and the
# resource path as message attributes. Every route's integration response maps to the status the
# caller asks for, so a "500 stage" still records each request it was sent.

_TEMPLATE = (
    "#set($src = $input.params().header.get('x-order-src'))"
    "#if(!$src || $src == '')#set($src = 'none')#{end}"
    "Action=SendMessage&MessageBody=$util.urlEncode($input.body)"
    "&MessageAttribute.1.Name=pathId&MessageAttribute.1.Value.DataType=String"
    "&MessageAttribute.1.Value.StringValue=$util.urlEncode($input.params().path.get('id'))"
    "&MessageAttribute.2.Name=orderSrc&MessageAttribute.2.Value.DataType=String"
    "&MessageAttribute.2.Value.StringValue=$util.urlEncode($src)"
    "&MessageAttribute.3.Name=route&MessageAttribute.3.Value.DataType=String"
    "&MessageAttribute.3.Value.StringValue=$util.urlEncode($context.resourcePath)"
)


def _queue(ctx, prefix):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]
    return url, arn, name


def _role(ctx, prefix, principal, policy):
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": principal},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": "xsvc-apigateway-1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    time.sleep(10)  # IAM propagation has no pollable condition; the first-use retry is the fix
    return arn


def _delete_rest_api(apigw, api_id):
    deadline = time.monotonic() + 120
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() > deadline:
                raise RuntimeError(f"rest api {api_id}: {code}") from e
            time.sleep(10)


def _rest_api_to_queue(ctx, account, sink_name, sink_arn, routes):
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-apigw1-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    role_arn = _role(ctx, "sim2real-xsvc-apigw1-gw-", "apigateway.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink_arn}],
    })
    root = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"]
                if r["path"] == "/")
    for part, status in routes.items():
        parent = apigw.create_resource(restApiId=api_id, parentId=root, pathPart=part)["id"]
        item = apigw.create_resource(restApiId=api_id, parentId=parent, pathPart="{id}")["id"]
        apigw.put_method(restApiId=api_id, resourceId=item, httpMethod="POST",
                         authorizationType="AWS_IAM",
                         requestParameters={"method.request.path.id": True})
        apigw.put_integration(
            restApiId=api_id, resourceId=item, httpMethod="POST", type="AWS",
            integrationHttpMethod="POST",
            uri=f"arn:aws:apigateway:{ctx.region}:sqs:path/{account}/{sink_name}",
            credentials=role_arn,
            requestParameters={
                "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"},
            requestTemplates={"application/json": _TEMPLATE},
            passthroughBehavior="NEVER",
        )
        apigw.put_method_response(restApiId=api_id, resourceId=item, httpMethod="POST",
                                  statusCode=status)
        apigw.put_integration_response(
            restApiId=api_id, resourceId=item, httpMethod="POST", statusCode=status,
            selectionPattern="",
            responseTemplates={"application/json": json.dumps({"stage_status": int(status)})},
        )
    stage = "v1"
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    return api_id, stage


def _stage_url(ctx, api_id, stage, path):
    return f"{ctx.rest_api_url(api_id, stage)}/{path}"


def _signed_post(ctx, url, body, headers):
    creds = ctx.client("sts")._request_signer._credentials.get_frozen_credentials()
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json", **headers}
    req = AWSRequest(method="POST", url=url, data=data, headers=hdrs)
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    raw = urllib.request.Request(url, data=data, method="POST", headers=dict(req.headers))
    try:
        with urllib.request.urlopen(raw, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except urllib.error.URLError as e:
        return None, repr(e.reason)


def _poll_signed_post(ctx, url, body, headers, expected, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _signed_post(ctx, url, body, headers)
        if last[0] == expected:
            return last
        time.sleep(5)
    raise AssertionError(f"POST {url} never returned {expected}; last={last!r}")


def _marker_of(msg):
    try:
        body = json.loads(msg["Body"])
    except ValueError:
        return None
    if isinstance(body.get("wrapped"), dict):
        return body["wrapped"].get("marker")
    if isinstance(body.get("detail"), dict):
        return body["detail"].get("marker")
    return body.get("marker")


def _attr(msg, name):
    return msg.get("MessageAttributes", {}).get(name, {}).get("StringValue")


def _receive(sqs, url, pred, want, timeout_s, seen=None):
    """Drain the queue until `want` messages satisfying `pred` have been read or the bound
    expires, deleting every message read (the non-matching ones are appended to `seen` when
    given, so an absence assertion can inspect them); returns the matching ones, possibly fewer."""
    found, other = [], ([] if seen is None else seen)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(found) < want:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   MessageAttributeNames=["All"], AttributeNames=["All"])
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            (found if pred(m) else other).append(m)
    return found


def _collect(sqs, url, pred, want, timeout_s, seen=None):
    """`_receive`, raising naming what did arrive if fewer than `want` match within the bound."""
    other = [] if seen is None else seen
    found = _receive(sqs, url, pred, want, timeout_s, seen=other)
    if len(found) < want:
        raise AssertionError(
            f"{len(found)}/{want} expected messages reached {url} within {timeout_s}s; "
            f"other bodies seen: {[m['Body'][:200] for m in other]!r}")
    return found


def _drain_for(sqs, url, seconds):
    """Read and delete everything that arrives on the queue for `seconds`."""
    seen = []
    deadline = time.monotonic() + seconds
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return seen
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=max(1, min(5, int(left))),
                                   MessageAttributeNames=["All"], AttributeNames=["All"])
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            seen.append(m)


def _bus_and_rule(ctx, pattern, bus=None):
    """A custom bus (unless one is passed in) and an ENABLED rule on it."""
    events = ctx.client("events")
    if bus is None:
        bus = ctx.unique_name("sim2real-xsvc-apigw1-bus-")
        events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    rule = ctx.unique_name("sim2real-xsvc-apigw1-rule-")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, State="ENABLED", EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))
    return bus, rule, rule_arn


def _put_target(ctx, bus, rule, target):
    events = ctx.client("events")
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=[target])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus,
                                                 Ids=[target["Id"]]))
    assert resp["FailedEntryCount"] == 0, f"put_targets refused {target['Id']!r}: {resp!r}"


def _dlq_for_rule(ctx, prefix, rule_arn):
    """A queue EventBridge may dead-letter into, scoped to this rule by aws:SourceArn."""
    url, arn, _ = _queue(ctx, prefix)
    ctx.client("sqs").set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}],
    })})
    return url, arn


def _deliver_with_retry(sqs, url, publish, sent, attempt_s, total_s):
    deadline = time.monotonic() + total_s
    while time.monotonic() < deadline:
        publish()
        found = _receive(sqs, url, lambda m: _marker_of(m) in sent, want=1, timeout_s=attempt_s)
        if found:
            return found[0]
    raise AssertionError(f"no published event ({len(sent)} attempts) reached the stage's "
                         f"sink within {total_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
