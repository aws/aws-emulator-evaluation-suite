"""xsvc-apigatewayv2-1-putevents-subtype-routes-to-custom-bus-rule-queue."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigatewayv2-1-putevents-subtype-routes-to-custom-bus-rule-queue"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "events", "sqs"]

_SOURCE = "app.orders"
_DETAIL_TYPE = "OrderPlaced"
# The near-miss rule differs from the posted detail-type only by letter case. EventBridge string
# matching is exact and case-sensitive, so this rule must never fire for "OrderPlaced".
_NEAR_MISS_DETAIL_TYPE = "orderplaced"


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An HTTP API EventBridge-PutEvents integration puts the mapped event on a custom bus; the rule
    queue receives it with the returned EventId, and a case-folded detail-type rule does not match.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    marker = ctx.unique_name("sim2real-xsvc-order-")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus_name = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus_name, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    match_url, match_arn = _create_queue(ctx, "match")
    near_url, near_arn = _create_queue(ctx, "nearmiss")
    _create_rule_to_queue(
        ctx, bus_name, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}, match_url, match_arn
    )
    _create_rule_to_queue(
        ctx,
        bus_name,
        {"source": [_SOURCE], "detail-type": [_NEAR_MISS_DETAIL_TYPE]},
        near_url,
        near_arn,
    )

    credentials_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["events:PutEvents"], "Resource": bus_arn}],
        },
    )

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-ebsubtype"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationSubtype="EventBridge-PutEvents",
        PayloadFormatVersion="1.0",
        CredentialsArn=credentials_arn,
        RequestParameters=_putevents_params(bus_name),
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="POST /orders", Target=f"integrations/{integration_id}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )

    stored = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert stored.get("IntegrationSubtype") == "EventBridge-PutEvents", (
        f"GetIntegration must report the EventBridge-PutEvents subtype, got "
        f"{stored.get('IntegrationSubtype')!r}"
    )
    assert (stored.get("RequestParameters") or {}).get("EventBusName") == bus_name, (
        f"the static EventBusName must be stored as authored, got "
        f"{(stored.get('RequestParameters') or {}).get('EventBusName')!r}"
    )

    url = f"{ctx.stage_url(api_endpoint, '$default')}/orders"
    detail = {"orderId": marker, "amount": 42, "items": ["sku-1", "sku-2"]}
    body = {"source": _SOURCE, "detailType": _DETAIL_TYPE, "detail": detail}

    # The HTTP poll absorbs IAM propagation of CredentialsArn.
    status, _, text = _poll_http(
        ctx,
        url,
        method="POST",
        body=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        accept=lambda s: s == 200,
        description="POST /orders reaching the EventBridge-PutEvents integration",
    )
    resp = json.loads(text)
    assert resp.get("FailedEntryCount") == 0, (
        f"the PutEvents response passed through to the client must report FailedEntryCount 0, "
        f"got {text[:300]!r}"
    )
    entries = resp.get("Entries") or []
    assert len(entries) == 1 and entries[0].get("EventId"), (
        f"one request must put exactly one entry carrying an EventId, got {text[:300]!r}"
    )
    event_id = entries[0]["EventId"]

    arrived = _poll_until(
        ctx,
        lambda: _drain_queue(sqs, match_url),
        lambda msgs: bool(msgs),
        timeout_s=90.0,
        interval_s=2.0,
        description=f"the OrderPlaced event arriving on the matching rule's queue {match_url}",
    )
    envelopes = [json.loads(m["Body"]) for m in arrived]
    ids = [e.get("id") for e in envelopes]
    assert event_id in ids, (
        f"the event the consumer reads must be the one the client was told about: response "
        f"EventId {event_id!r}, queue envelope ids {ids!r}"
    )
    env = envelopes[ids.index(event_id)]
    assert env.get("source") == _SOURCE, f"envelope source {env.get('source')!r}, expected {_SOURCE!r}"
    assert env.get("detail-type") == _DETAIL_TYPE, (
        f"envelope detail-type {env.get('detail-type')!r}, expected {_DETAIL_TYPE!r}"
    )
    assert env.get("detail") == detail, (
        f"the envelope detail must be exactly the mapped $request.body.detail object {detail!r}, "
        f"got {env.get('detail')!r}"
    )
    assert env.get("account") == account and env.get("region") == ctx.region, (
        f"the envelope must name this account/region ({account!r}, {ctx.region!r}), got "
        f"({env.get('account')!r}, {env.get('region')!r})"
    )
    assert all(e.get("detail", {}).get("orderId") == marker for e in envelopes), (
        f"only this check's order may arrive on its queue, got {envelopes!r}"
    )

    # Positive control for queue B, ordered after the OrderPlaced event: the near miss itself is
    # delivered there, and nothing drained up to its arrival is the OrderPlaced event.
    near_detail = {"orderId": f"{marker}-near", "amount": 1, "items": []}
    status, _, text = _http_routed(
        "POST",
        url,
        body=json.dumps(
            {"source": _SOURCE, "detailType": _NEAR_MISS_DETAIL_TYPE, "detail": near_detail}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert status == 200, f"the near-miss POST must be accepted, got {status}: {text[:300]!r}"
    near_id = json.loads(text)["Entries"][0]["EventId"]
    near_envs: list[dict] = []

    def _drain_near():
        near_envs.extend(json.loads(m["Body"]) for m in _drain_queue(sqs, near_url))
        return near_envs

    _poll_until(
        ctx,
        _drain_near,
        lambda envs: any(e.get("id") == near_id for e in envs),
        timeout_s=90.0,
        interval_s=2.0,
        description=f"the {_NEAR_MISS_DETAIL_TYPE!r} event arriving on the near-miss queue",
    )
    assert not [e for e in near_envs if e.get("id") == event_id], (
        f"detail-type {_DETAIL_TYPE!r} must not match a rule on {_NEAR_MISS_DETAIL_TYPE!r}, but the "
        f"near-miss queue received the {_DETAIL_TYPE!r} event {event_id!r}"
    )
    assert [e.get("id") for e in near_envs] and all(
        e.get("id") == near_id and e.get("detail-type") == _NEAR_MISS_DETAIL_TYPE for e in near_envs
    ), (
        f"the near-miss queue must hold only the {_NEAR_MISS_DETAIL_TYPE!r} event {near_id!r}, got "
        f"{near_envs!r}"
    )
    leaked = [json.loads(m["Body"]) for m in _drain_queue(sqs, match_url)]
    assert not [e for e in leaked if e.get("id") == near_id], (
        f"the {_NEAR_MISS_DETAIL_TYPE!r} event must not reach the {_DETAIL_TYPE!r} rule's queue, "
        f"got {leaked!r}"
    )


def _putevents_params(bus_name: str) -> dict:
    return {
        "Source": "$request.body.source",
        "DetailType": "$request.body.detailType",
        "Detail": "$request.body.detail",
        "EventBusName": bus_name,
    }


_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, kind):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, kind), tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_rule_to_queue(ctx, bus_name, pattern, queue_url, queue_arn):
    events = ctx.client("events")
    rule_name = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=_xsvc_tags_kv(),
    )["RuleArn"]

    def _delete_rule():
        ev = ctx.client("events")
        try:
            ev.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["q"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        ev.delete_rule(Name=rule_name, EventBusName=bus_name)

    ctx.on_cleanup(_delete_rule)
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )
    out = events.put_targets(
        Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "q", "Arn": queue_arn}]
    )
    assert out.get("FailedEntryCount") == 0, f"PutTargets failed: {out!r}"
    return rule_arn


def _drain_queue(sqs, queue_url):
    """Receive-and-delete every visible message and return them."""
    out = []
    for _ in range(5):
        messages = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not messages:
            break
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        out.extend(messages)
    return out


def _deadline(ctx, timeout_s):
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout (capped by the run budget)."""
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _http_routed(method, url, body=None, headers=None, timeout_s=60.0):
    """Send a request to an already-deployed route, retrying only the route-not-found 404: a fresh
    $default auto-deployment is eventually consistent; that 404 never invoked the integration."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, hdrs, text = _http(method, url, body=body, headers=headers)
        if not (status == 404 and text.strip() == '{"message":"Not Found"}'):
            return status, hdrs, text
        if time.monotonic() >= deadline:
            return status, hdrs, text
        time.sleep(2.0)


def _poll_http(
    ctx,
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=180.0,
    interval_s=2.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status) and return (status, headers, text); raise on timeout.
    Also absorbs IAM propagation of a new CredentialsArn, which surfaces as early 5xx responses."""
    deadline = _deadline(ctx, timeout_s)
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers, timeout_s=20)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
