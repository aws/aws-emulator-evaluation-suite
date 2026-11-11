"""xsvc-apigateway-1-target-role-without-execute-api-invoke-is-denied."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-1-target-role-without-execute-api-invoke-is-denied"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "events", "iam", "sqs"]

_SOURCE = "sim2real.orders"
_DETAIL_TYPE = "OrderPlaced"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An API Gateway target whose role lacks execute-api:Invoke is dead-lettered with the denial while a
    twin rule with Invoke delivers the same event; granting Invoke makes the denied target deliver."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    sink_url, sink_arn, sink_name = _queue(ctx, "sim2real-xsvc-apigw1-sink-")
    api_id, stage = _rest_api_to_queue(ctx, account, sink_name, sink_arn,
                                       routes={"orders": "200"})
    warm = ctx.unique_name("warm-")
    _poll_signed_post(ctx, _stage_url(ctx, api_id, stage, "orders/w-1"),
                      {"marker": warm}, {"x-order-src": "runner"}, expected=200)
    _collect(sqs, sink_url, lambda m: _marker_of(m) == warm, want=1, timeout_s=60)

    pattern = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}
    target_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/{stage}/POST/orders/*"
    bus, good_rule, _ = _bus_and_rule(ctx, pattern)
    good_role = _role(ctx, "sim2real-xsvc-apigw1-good-", "events.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke",
                       "Resource": target_arn}],
    })
    _put_target(ctx, bus, good_rule, {
        "Id": "good", "Arn": target_arn, "RoleArn": good_role,
        "HttpParameters": {"PathParameterValues": ["$.detail.id"],
                           "HeaderParameters": {"x-order-src": "rule-good"}},
    })

    def _entry(marker):
        return {"EventBusName": bus, "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"id": f"ord-{marker[-6:]}", "marker": marker})}

    def _from(src):
        return lambda m: _attr(m, "orderSrc") == src

    sent: dict[str, dict] = {}

    def _publish():
        marker = ctx.unique_name("ctl-")
        r = events.put_events(Entries=[_entry(marker)])
        assert r["FailedEntryCount"] == 0, f"put_events rejected the entry: {r!r}"
        sent[marker] = {}

    # The denied twin's rule, role and DLQ are created BEFORE the control warm-up so their IAM
    # and queue-policy propagation overlaps it: a DLQ whose policy has not propagated drops the
    # dead letter silently.
    _, bad_rule, bad_rule_arn = _bus_and_rule(ctx, pattern, bus=bus)
    bad_role = _role(ctx, "sim2real-xsvc-apigw1-deny-", "events.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "execute-api:InvalidateCache",
                       "Resource": target_arn}],
    })
    bad_role_name = bad_role.rsplit("/", 1)[-1]
    dlq_url, dlq_arn = _dlq_for_rule(ctx, "sim2real-xsvc-apigw1-dlq-", bad_rule_arn)

    # Positive control: the permitted role's propagation is absorbed before the twin is wired.
    _deliver_with_retry(sqs, sink_url, _publish, sent, attempt_s=25, total_s=180)

    _put_target(ctx, bus, bad_rule, {
        "Id": "denied", "Arn": target_arn, "RoleArn": bad_role,
        "HttpParameters": {"PathParameterValues": ["$.detail.id"],
                           "HeaderParameters": {"x-order-src": "rule-denied"}},
        "DeadLetterConfig": {"Arn": dlq_arn},
        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
    })

    # One PutEvents entry fans out to both rules. Bounded re-publish until the denied twin's
    # dead letter lands; EVERY attempted marker is held to the absence assertion below.
    attempted, seen, latencies = [], [], []
    dead = None
    deadline = time.monotonic() + 240
    while dead is None and time.monotonic() < deadline:
        marker = ctx.unique_name("evt-")
        attempted.append(marker)
        t0 = time.monotonic()
        r = events.put_events(Entries=[_entry(marker)])
        assert r["FailedEntryCount"] == 0, f"put_events rejected the entry: {r!r}"
        _collect(sqs, sink_url, lambda m, k=marker: _marker_of(m) == k
                 and _from("rule-good")(m), want=1, timeout_s=60, seen=seen)
        latencies.append(time.monotonic() - t0)
        found = _receive(sqs, dlq_url, lambda m: _marker_of(m) in attempted, want=1,
                         timeout_s=45)
        dead = found[0] if found else None
        # A dead letter without the stage's 403 means EventBridge could not yet use the fresh
        # role (IAM propagation): discard it, its marker stays under the absence assertion.
        if dead is not None and not (
            dead.get("MessageAttributes", {}).get("ERROR_MESSAGE", {}).get("StringValue") or ""
        ).startswith('Got status code "403"'):
            dead = None
    assert dead is not None, (
        f"the denied twin never dead-lettered any of {len(attempted)} events in 240s; "
        f"denied-path messages at the stage: "
        f"{[m['Body'][:120] for m in seen if _from('rule-denied')(m)]!r}")
    marker = _marker_of(dead)
    attrs = {k: v.get("StringValue") for k, v in dead.get("MessageAttributes", {}).items()}
    assert attrs.get("RULE_ARN") == bad_rule_arn, f"DLQ RULE_ARN {attrs.get('RULE_ARN')!r}"
    assert attrs.get("TARGET_ARN") == target_arn, f"DLQ TARGET_ARN {attrs.get('TARGET_ARN')!r}"
    # AWS classifies the stage's 403 to the unauthorised signer as
    # NO_PERMISSIONS, and the message quotes the status and the substituted request line.
    assert attrs.get("ERROR_CODE") == "NO_PERMISSIONS", (
        f"DLQ ERROR_CODE {attrs.get('ERROR_CODE')!r}; all attributes {attrs!r}")
    expected_line = (f'Got status code "403" while trying to invoke "POST '
                     f'{ctx.api_url(api_id, stage)}/orders/ord-{marker[-6:]}"')
    # message varies: AWS appends the Request ID of its own call to the stage, minted per
    # delivery attempt; every other byte of the message is asserted.
    message = attrs.get("ERROR_MESSAGE") or ""
    request_id = message.rpartition("; Request ID: ")[2].partition(";")[0]
    expected_message = (f"{expected_line}. (Service: api_gateway; Status Code: 403; "
                        f"Error Code: Forbidden; Request ID: {request_id}; Proxy: null)")
    assert message == expected_message, (
        f"DLQ ERROR_MESSAGE {message!r} != {expected_message!r}")

    seen += _drain_for(sqs, sink_url, max(10.0, 3 * max(latencies)))
    leaked = [m["Body"] for m in seen
              if _marker_of(m) in attempted and _from("rule-denied")(m)]
    assert not leaked, (
        f"a role without execute-api:Invoke reached the AWS_IAM stage: {leaked!r}")

    # Repair the one broken thing: grant Invoke to the denied role, and the same target
    # delivers (bounded retry -- IAM propagation has no pollable condition).
    iam.put_role_policy(RoleName=bad_role_name, PolicyName="inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke",
                       "Resource": target_arn}],
    }))
    repaired: dict[str, dict] = {}

    def _publish_repaired():
        m = ctx.unique_name("fix-")
        r = events.put_events(Entries=[_entry(m)])
        assert r["FailedEntryCount"] == 0, f"put_events rejected the entry: {r!r}"
        repaired[m] = {}

    deadline = time.monotonic() + 180
    hit = None
    while hit is None and time.monotonic() < deadline:
        _publish_repaired()
        found = _receive(sqs, sink_url, lambda m: _marker_of(m) in repaired
                         and _from("rule-denied")(m), want=1, timeout_s=25)
        hit = found[0] if found else None
    assert hit is not None, (
        f"after granting execute-api:Invoke the twin target still never reached the stage "
        f"({len(repaired)} attempts in 180s)")


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
    # IAM propagation has no pollable condition: every first use of the role retries until it lands.
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
