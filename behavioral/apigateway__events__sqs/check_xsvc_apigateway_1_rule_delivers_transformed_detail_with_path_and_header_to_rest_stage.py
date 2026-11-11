"""xsvc-apigateway-1-rule-delivers-transformed-detail-with-path-and-header-to-rest-stage."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-1-rule-delivers-transformed-detail-with-path-and-header-to-rest-stage"
GROUP = "data-format"
SERVICES = ["apigateway", "events", "iam", "sqs"]

_SOURCE = "sim2real.orders"
_DETAIL_TYPE = "OrderPlaced"


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An EventBridge rule targeting a deployed REST stage POSTs the InputTransformer payload with
    the path wildcard taken from $.detail.id and a header from $.detail.src; the stage's SQS
    integration records all three, and a direct signed POST first proves the stage records."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    sink_url, sink_arn, sink_name = _queue(ctx, "sim2real-xsvc-apigw1-sink-")
    api_id, stage = _rest_api_to_queue(ctx, account, sink_name, sink_arn,
                                       routes={"orders": "200"})

    # Direct signed POST: absorbs the gateway->SQS role propagation and proves the stage
    # records what it receives, independently of EventBridge.
    warm = ctx.unique_name("warm-")
    status, body = _poll_signed_post(ctx, _stage_url(ctx, api_id, stage, "orders/w-1"),
                                     {"marker": warm}, {"x-order-src": "runner"}, expected=200)
    assert json.loads(body) == {"stage_status": 200}, f"stage answered {body!r}"
    got = _collect(sqs, sink_url, lambda m: _marker_of(m) == warm, want=1, timeout_s=60)
    assert (_attr(got[0], "pathId"), _attr(got[0], "orderSrc")) == ("w-1", "runner"), (
        f"runner POST recorded pathId={_attr(got[0], 'pathId')!r} "
        f"orderSrc={_attr(got[0], 'orderSrc')!r}, expected 'w-1'/'runner'"
    )

    bus, rule, _ = _bus_and_rule(ctx, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})
    target_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/{stage}/POST/orders/*"
    role_arn = _role(ctx, "sim2real-xsvc-apigw1-evb-", "events.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke",
                       "Resource": target_arn}],
    })
    _put_target(ctx, bus, rule, {
        "Id": "stage",
        "Arn": target_arn,
        "RoleArn": role_arn,
        "HttpParameters": {
            "PathParameterValues": ["$.detail.id"],
            "HeaderParameters": {"x-order-src": "$.detail.src"},
        },
        "InputTransformer": {
            "InputPathsMap": {"d": "$.detail", "t": "$.detail-type"},
            "InputTemplate": '{"wrapped": <d>, "kind": <t>}',
        },
    })

    # Bounded first-use retry for the EventBridge role's IAM propagation: a fresh marker per
    # attempt, and whichever attempt lands is the one asserted on.
    sent: dict[str, dict] = {}

    def _publish():
        marker = ctx.unique_name("evt-")
        detail = {"id": f"ord-{marker[-6:]}", "src": "checkout-web", "marker": marker,
                  "amount": 42, "lines": [{"sku": "A-1", "qty": 2}]}
        r = events.put_events(Entries=[{"EventBusName": bus, "Source": _SOURCE,
                                        "DetailType": _DETAIL_TYPE,
                                        "Detail": json.dumps(detail)}])
        assert r["FailedEntryCount"] == 0, f"put_events rejected the entry: {r!r}"
        sent[marker] = detail

    msg = _deliver_with_retry(ctx, sqs, sink_url, _publish, sent, attempt_s=25, total_s=180)
    payload = json.loads(msg["Body"])
    assert set(payload) == {"wrapped", "kind"}, (
        f"stage received keys {sorted(payload)!r}; the InputTemplate produces exactly "
        f"wrapped+kind, so this is not the transformed payload: {payload!r}"
    )
    detail = sent[payload["wrapped"]["marker"]]
    assert payload["wrapped"] == detail, (
        f"wrapped detail {payload['wrapped']!r} is not the published detail {detail!r}"
    )
    assert payload["kind"] == _DETAIL_TYPE, (
        f"<t> resolved to {payload['kind']!r}, expected the detail-type {_DETAIL_TYPE!r}"
    )
    assert _attr(msg, "pathId") == detail["id"], (
        f"stage path parameter was {_attr(msg, 'pathId')!r}; PathParameterValues $.detail.id "
        f"should have substituted {detail['id']!r}"
    )
    assert _attr(msg, "orderSrc") == detail["src"], (
        f"stage saw header x-order-src={_attr(msg, 'orderSrc')!r}, expected {detail['src']!r} "
        f"from HeaderParameters $.detail.src"
    )
    assert _attr(msg, "route") == "/orders/{id}", (
        f"the request was routed to resource {_attr(msg, 'route')!r}, expected '/orders/{{id}}'"
    )


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
    """Retry the POST every 2 s until it answers ``expected`` (the gateway role may still be
    propagating); the deadline is capped by the run budget."""
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = _signed_post(ctx, url, body, headers)
        if last[0] == expected:
            return last
        time.sleep(2)
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


def _deadline(ctx, timeout_s):
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _deliver_with_retry(ctx, sqs, url, publish, sent, attempt_s, total_s):
    deadline = _deadline(ctx, total_s)
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
