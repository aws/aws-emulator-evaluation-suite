"""xsvc-appsync-1-eventbridge-datasource-mutation-routes-to-matching-rule-only."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-appsync-1-eventbridge-datasource-mutation-routes-to-matching-rule-only"
GROUP = "event-propagation"
SERVICES = ["appsync", "events", "sqs"]

# Prefix marking a FAIL as an unimplemented endpoint data plane rather than a wrong answer.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_SOURCE = "app.orders"
_DETAIL_TYPE = "OrderPlaced"

_SCHEMA = """schema {
    query: Query
    mutation: Mutation
}

type Query {
    ping: String
}

type PutEventsResult {
    failedCount: Int!
    eventIds: [String!]!
}

type Mutation {
    placeOrder(orderId: ID!, tier: String!, resource: String!): PutEventsResult
}
"""

# APPSYNC_JS unit resolver on an AMAZON_EVENTBRIDGE data source: the request handler IS the
# PutEvents call AppSync makes on the caller's behalf; the response handler projects the
# EventBridge PutEvents result ({Entries:[{EventId}], FailedEntryCount}) onto the GraphQL type.
_RESOLVER_CODE = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'PutEvents',
    events: [{
      source: 'app.orders',
      detailType: 'OrderPlaced',
      detail: { orderId: ctx.args.orderId, tier: ctx.args.tier },
      resources: [ctx.args.resource],
    }],
  };
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  return {
    failedCount: ctx.result.FailedEntryCount,
    eventIds: ctx.result.Entries.map((e) => e.EventId),
  };
}
"""

_MUTATION = (
    "mutation($o: ID!, $t: String!, $r: String!) "
    "{ placeOrder(orderId: $o, tier: $t, resource: $r) { failedCount eventIds } }"
)


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
    """An AMAZON_EVENTBRIDGE data-source mutation emits one event only the matching rule delivers.

    The gold queue gets exactly one envelope with the sent fields and AppSync's EventId; the silver
    rule's queue, proven live first, gets no gold order.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/tutorial-eventbridge-js.html
    """
    import requests

    appsync = ctx.client("appsync")
    events = ctx.client("events")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    queue_a = _create_queue(ctx)
    queue_b = _create_queue(ctx)
    _put_rule_with_sqs_target(
        ctx,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"tier": ["gold"]}},
        queue_a,
        bus=bus,
    )
    _put_rule_with_sqs_target(ctx, {"detail": {"tier": ["silver"]}}, queue_b, bus=bus)

    role_arn = _create_appsync_role(ctx, "events:PutEvents", bus_arn)

    api = appsync.create_graphql_api(
        name=_xname(ctx, "api"),
        authenticationType="API_KEY",
        tags=_xsvc_resource_tags(),
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    api_arn = api["arn"]
    graphql_url = api.get("uris", {}).get("GRAPHQL")
    assert graphql_url, f"GraphQL API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"

    _create_schema(appsync, api_id, _SCHEMA)
    ds = appsync.create_data_source(
        apiId=api_id,
        name="sim2real_eb_orders",
        type="AMAZON_EVENTBRIDGE",
        serviceRoleArn=role_arn,
        eventBridgeConfig={"eventBusArn": bus_arn},
    )["dataSource"]
    assert ds["eventBridgeConfig"]["eventBusArn"] == bus_arn, (
        f"data source bound to {ds.get('eventBridgeConfig')!r}, expected bus {bus_arn!r}"
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Mutation",
        fieldName="placeOrder",
        dataSourceName=ds["name"],
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=_RESOLVER_CODE,
    )
    api_key = appsync.create_api_key(apiId=api_id, description="sim2real-xsvc")["apiKey"]["id"]

    def place(order_id: str, tier: str) -> dict:
        return _graphql(
            ctx, requests,
            graphql_url,
            api_key,
            _MUTATION,
            {"o": order_id, "t": tier, "r": api_arn},
        )

    # Precondition: rule B's path is live, so its later silence means selectivity.
    silver_ids = _emit_until_delivered(ctx, place, "silver", queue_b["url"])

    # A fresh rule may drop an event before it goes live; each attempt uses a fresh orderId so
    # "exactly one" is asserted for the orderId that arrived.
    gold_ids: list[str] = []
    delivered: dict | None = None
    gold_resp: dict | None = None
    for _ in range(8):
        order_id = f"gold-{uuid.uuid4().hex[:12]}"
        body = _invoke_ok(ctx, place, order_id, "gold")
        gold_ids.append(order_id)
        gold_resp = body["data"]["placeOrder"]
        assert gold_resp["failedCount"] == 0, (
            f"PutEvents via AppSync reported failedCount={gold_resp['failedCount']!r}: {body!r}"
        )
        assert len(gold_resp["eventIds"]) == 1, (
            f"one event was sent but PutEvents returned eventIds={gold_resp['eventIds']!r}"
        )
        got, _ = _wait_for(
            ctx,
            queue_a["url"],
            lambda b, o=order_id: _order_id(b) == o,
            timeout_s=12.0,
        )
        if got:
            delivered = {"order_id": order_id, "msgs": got, "resp": gold_resp}
            break
    if delivered is None:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: none of {len(gold_ids)} gold orders sent through the AppSync "
            f"EventBridge data source reached queue A via rule A (orderIds {gold_ids!r})"
        )

    order_id = delivered["order_id"]
    # Exactly one copy: keep draining A for a further window and count copies of this order.
    later = [
        m for m in _collect(ctx, queue_a["url"], window_s=10.0)
        if _order_id(_body(m)) == order_id
    ]
    copies = delivered["msgs"] + later
    assert len(copies) == 1, (
        f"queue A received {len(copies)} copies of order {order_id!r} from ONE mutation: "
        f"{[_body(m) for m in copies]!r}"
    )
    env = _body(copies[0])
    assert isinstance(env, dict), f"queue A message body is not an event envelope: {env!r}"
    assert env.get("source") == _SOURCE, f"source was {env.get('source')!r}, sent {_SOURCE!r}"
    assert env.get("detail-type") == _DETAIL_TYPE, (
        f"detail-type was {env.get('detail-type')!r}, sent {_DETAIL_TYPE!r}"
    )
    assert env.get("detail") == {"orderId": order_id, "tier": "gold"}, (
        f"detail was {env.get('detail')!r}, sent {{'orderId': {order_id!r}, 'tier': 'gold'}}"
    )
    assert env.get("resources") == [api_arn], (
        f"resources was {env.get('resources')!r}, sent {[api_arn]!r}"
    )
    assert env.get("id") == delivered["resp"]["eventIds"][0], (
        f"delivered envelope id {env.get('id')!r} is not the EventId AppSync returned "
        f"{delivered['resp']['eventIds'][0]!r}"
    )

    # Asserted only after delivery to A is confirmed; late silver copies of the precondition are
    # legitimate and ignored.
    leaked = [
        _body(m) for m in _collect(ctx, queue_b["url"], window_s=15.0)
        if _order_id(_body(m)) not in silver_ids
    ]
    assert leaked == [], (
        f"queue B (rule detail.tier=='silver') received non-silver event(s) after the gold order "
        f"was delivered to A — routing is not selective: {leaked!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_schema(appsync, api_id: str, definition: str) -> None:
    appsync.start_schema_creation(apiId=api_id, definition=definition.encode())
    deadline = time.monotonic() + 90
    status: dict = {}
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)
        if status.get("status") in ("SUCCESS", "FAILED"):
            break
        time.sleep(1.5)
    assert status.get("status") == "SUCCESS", f"schema creation did not succeed: {status!r}"


def _create_appsync_role(ctx, action: str, bus_arn: str) -> str:
    """An IAM role AppSync can assume, whose ONLY inline permission is `action` on the bus."""
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "appsync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-xsvc appsync eventbridge data source role",
        Tags=_xsvc_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="eventbridge",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": action, "Resource": bus_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="eventbridge"))
    # IAM propagation exposes no condition to poll; the AccessDenied retry at first use
    # (_invoke_ok) is what waits it out.
    return arn


def _graphql(ctx, requests, url: str, api_key: str, query: str, variables: dict) -> dict:
    """POST one GraphQL operation over the live endpoint; a transport failure is a data-plane FAIL."""
    try:
        routed_url, route_headers = ctx.endpoint_route(url)
        r = requests.post(
            routed_url,
            json={"query": query, "variables": variables},
            headers={"x-api-key": api_key, "Content-Type": "application/json", **route_headers},
            timeout=20,
        )
    except (requests.ConnectionError, requests.Timeout) as exc:  # classify, then fail with the sentinel
        raise AssertionError(
            f"{DATAPLANE_MARKER}: GraphQL endpoint {url!r} unreachable: {type(exc).__name__}: {exc}"
        ) from exc
    assert r.status_code == 200, (
        f"{DATAPLANE_MARKER}: GraphQL endpoint returned HTTP {r.status_code}: {r.text[:400]!r}"
    )
    return r.json()


def _is_iam_propagation_error(err: dict) -> bool:
    """True for the fresh role's IAM eventual consistency: AppSync not yet able to assume it, its
    session token not yet accepted by EventBridge, or the role not yet carrying the PutEvents grant."""
    error_type = err.get("errorType")
    if error_type == "EventBridge:AccessDeniedException":
        return True
    message = err.get("message") or ""
    if error_type == "EventBridge:EventBridgeException":
        return "The security token included in the request is invalid" in message
    return error_type == "Unauthorized" and "Unable to assume role" in message


def _invoke_ok(ctx, place, order_id: str, tier: str, timeout_s: float = 60.0) -> dict:
    """Invoke the mutation, retrying ONLY IAM propagation of the fresh data source role every 2 s
    until it succeeds; the deadline is capped by the run budget."""
    body: dict = {}
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        body = place(order_id, tier)
        errs = body.get("errors") or []
        if not errs:
            assert body.get("data", {}).get("placeOrder") is not None, (
                f"mutation returned neither errors nor data: {body!r}"
            )
            return body
        if not _is_iam_propagation_error(errs[0]):
            raise AssertionError(f"mutation for {order_id!r} failed unexpectedly: {errs!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"data source role never became usable for PutEvents (IAM propagation): {body!r}"
            )
        time.sleep(2)


def _emit_until_delivered(ctx, place, tier: str, queue_url: str, attempts: int = 8) -> list[str]:
    """Send fresh `tier` orders through the mutation until one lands on queue_url.

    Returns every orderId sent, so the caller can recognise late copies of them."""
    sent: list[str] = []
    for _ in range(attempts):
        oid = f"{tier}-{uuid.uuid4().hex[:12]}"
        _invoke_ok(ctx, place, oid, tier)
        sent.append(oid)
        got, _ = _wait_for(ctx, queue_url, lambda b: _order_id(b) in sent, timeout_s=12.0)
        if got:
            return sent
    raise AssertionError(
        f"{DATAPLANE_MARKER}: precondition failed — no {tier!r} order sent through the AppSync "
        f"EventBridge data source reached {queue_url} after {attempts} attempts ({sent!r})"
    )


def _order_id(body) -> Any:
    return body.get("detail", {}).get("orderId") if isinstance(body, dict) else None


def _create_queue(ctx) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _collect(ctx, queue_url, *, window_s=30.0, max_total=50):
    """Drain a queue over a bounded window, deleting and returning every message seen.

    An empty return is only meaningful once a positive delivery was observed elsewhere.
    """
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives.
    Returns (matched, others)."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(6.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _put_rule_with_sqs_target(ctx, pattern: dict, queue: dict, *, bus: str) -> str:
    """Create a rule on `bus` for `pattern`, grant it SendMessage on `queue`, attach the queue as
    target t1. Registers delete_rule + remove_targets teardown. Returns the rule name."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), Tags=_xsvc_tags_kv()
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=bus, Force=True))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    events.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=name, EventBusName=bus, Ids=["t1"]))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
