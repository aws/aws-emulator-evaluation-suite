"""xsvc-apigatewayv2-1-putevents-without-events-permission-denied-delivers-nothing."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigatewayv2-1-putevents-without-events-permission-denied-delivers-nothing"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "events", "sqs"]

_SOURCE = "app.orders"
_DETAIL_TYPE = "OrderPlaced"
_NEAR_MISS_DETAIL_TYPE = "orderplaced"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A PutEvents integration whose CredentialsArn role lacks events:PutEvents returns 400
    AccessDeniedException and delivers nothing, while a permitted sibling route delivers; granting
    the one missing permission makes the same route deliver to the matching queue."""
    marker = ctx.unique_name("sim2real-xsvc-order-")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

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

    # The refused route's role is created FIRST, so by the time the control route works its trust
    # policy has had at least as long to propagate. It holds a real events permission — just not
    # PutEvents — so the role is otherwise well-formed.
    denied_role_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["events:DescribeEventBus"], "Resource": bus_arn}
            ],
        },
    )
    denied_role_name = denied_role_arn.rsplit("/", 1)[-1]
    allowed_role_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["events:PutEvents"], "Resource": bus_arn}],
        },
    )

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-ebdenied"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    for route, role_arn in (("/allowed", allowed_role_arn), ("/denied", denied_role_arn)):
        integration_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationSubtype="EventBridge-PutEvents",
            PayloadFormatVersion="1.0",
            CredentialsArn=role_arn,
            RequestParameters=_putevents_params(bus_name),
        )["IntegrationId"]
        agw.create_route(
            ApiId=api_id, RouteKey=f"POST {route}", Target=f"integrations/{integration_id}"
        )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    allowed_url = f"{ctx.stage_url(api_endpoint, '$default')}/allowed"
    denied_url = f"{ctx.stage_url(api_endpoint, '$default')}/denied"

    def _order(tag):
        return {
            "source": _SOURCE,
            "detailType": _DETAIL_TYPE,
            "detail": {"orderId": f"{marker}-{tag}", "amount": 7},
        }

    def _await_order(tag):
        """Drain the matching queue until the event for `tag` arrives; return everything drained."""
        seen = []

        def probe():
            seen.extend(json.loads(m["Body"]) for m in _drain_queue(sqs, match_url))
            return seen

        _poll_until(
            ctx,
            probe,
            lambda envs: any(e.get("detail", {}).get("orderId") == f"{marker}-{tag}" for e in envs),
            timeout_s=90.0,
            interval_s=2.0,
            description=f"order {tag!r} arriving on the matching rule's queue",
        )
        return seen

    # Beat 1 — the control route delivers (absorbs IAM propagation; establishes the barrier).
    status, _, text = _poll_http(
        ctx,
        allowed_url,
        method="POST",
        body=json.dumps(_order("control-1")).encode(),
        headers={"Content-Type": "application/json"},
        accept=lambda s: s == 200,
        description="POST /allowed reaching the EventBridge-PutEvents integration",
    )
    assert json.loads(text).get("FailedEntryCount") == 0, f"control PutEvents failed: {text!r}"
    seen = _await_order("control-1")

    # Beat 2 — the refused request: exact status and error code.
    # NOT a gateway 5xx. The gateway assumes the role, calls
    # PutEvents, and passes EventBridge's own 400 AccessDeniedException through to the client.
    bad_status, _, bad_text = _http_routed(
        "POST",
        denied_url,
        body=json.dumps(_order("denied")).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert bad_status == 400, (
        f"a PutEvents integration whose role lacks events:PutEvents must surface EventBridge's "
        f"own refusal as 400, got {bad_status}: {bad_text[:300]!r}"
    )
    bad_body = json.loads(bad_text)
    # The error code is read the way every SDK reads it: the part of __type after any '#'.
    assert (bad_body.get("__type") or "").rsplit("#", 1)[-1] == "AccessDeniedException", (
        f"the refusal must be EventBridge's AccessDeniedException passed through, got "
        f"{bad_text[:300]!r}"
    )
    # The denied principal is the route's CredentialsArn role assumed under a session name the
    # gateway mints per request; that one segment is read back, everything else is built from
    # what this check created.
    bad_message = bad_body.get("Message") or ""
    principal_prefix = f"User: arn:aws:sts::{bus_arn.split(':')[4]}:assumed-role/{denied_role_name}/"
    session = bad_message[len(principal_prefix):].split(" ", 1)[0]
    assert bad_message == (
        f"{principal_prefix}{session} is not authorized to perform: events:PutEvents on "
        f"resource: {bus_arn} because no identity-based policy allows the events:PutEvents "
        f"action"
    ) and session, (
        f"the refusal must be EventBridge's exact AccessDenied message for the route's own "
        f"CredentialsArn role {denied_role_name!r} on this check's bus {bus_arn!r}, got "
        f"{bad_message!r}"
    )

    # Beat 3 — differential barrier: a control event posted AFTER the refused one arrives, and
    # by then the refused event (had it been put) would have travelled the same rule.
    status, _, text = _http_routed(
        "POST",
        allowed_url,
        body=json.dumps(_order("control-2")).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert status == 200, f"the control route must still accept, got {status}: {text[:300]!r}"
    seen += _await_order("control-2")
    _assert_queue_empty(
        sqs,
        match_url,
        because="nothing further may arrive on the matching queue after the control barrier",
    )
    denied_ids = [e for e in seen if e.get("detail", {}).get("orderId") == f"{marker}-denied"]
    assert not denied_ids, (
        f"the refused request's event must never reach the matching rule's queue, got {denied_ids!r}"
    )
    _assert_queue_empty(
        sqs,
        near_url,
        because="the near-miss rule's queue must stay empty — nothing posted matches it",
    )

    # Beat 4 — repair the ONE missing permission; the same route now delivers.
    iam.put_role_policy(
        RoleName=denied_role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["events:PutEvents"], "Resource": bus_arn}
                ],
            }
        ),
    )
    status, _, text = _poll_http(
        ctx,
        denied_url,
        method="POST",
        body=json.dumps(_order("repaired")).encode(),
        headers={"Content-Type": "application/json"},
        accept=lambda s: s == 200,
        description="POST /denied after granting events:PutEvents to its role",
    )
    assert json.loads(text).get("FailedEntryCount") == 0, f"repaired PutEvents failed: {text!r}"
    after = _await_order("repaired")
    assert not [e for e in after if e.get("detail", {}).get("orderId") == f"{marker}-denied"], (
        f"the originally refused event must not surface after the repair, got {after!r}"
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
    """Receive-and-delete every visible message; return them. The list IS the assertion."""
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


def _assert_queue_empty(sqs, queue_url, *, because):
    """One read after the ordered control: nothing is visible, and the queue's own reported depth
    agrees as a second observable."""
    arrived = _drain_queue(sqs, queue_url)
    assert not arrived, (
        f"{because}: {len(arrived)} message(s) arrived: {[m['Body'][:200] for m in arrived]!r}"
    )
    depth = int(
        sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
    )
    assert depth == 0, f"{because}: the queue reports ApproximateNumberOfMessages == {depth}"


def _deadline(ctx, timeout_s):
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
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
    """One logical request to a route that is ALREADY known to be deployed (an earlier request to
    this API succeeded). A fresh $default auto-deployment is eventually consistent across the
    gateway's fleet, so a request can still land on a node that answers the API's own
    route-not-found 404 ``{"message":"Not Found"}``; that answer means the integration was never
    invoked, so retrying it repeats nothing. Any other status is returned as the result."""
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
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout.

    This also absorbs IAM propagation: a brand-new CredentialsArn is not immediately usable by
    API Gateway, which surfaces as a 5xx on the first requests.
    """
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
