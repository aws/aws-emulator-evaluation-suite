"""eventbridge-datasource-role-without-put-events-denied."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-datasource-role-without-put-events-denied"
GROUP = "permission-chain"
SERVICES = ["appsync", "events", "sqs"]

# Marks a missing endpoint data plane, so it is reported as a failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_DENIED_ERROR_TYPE = "EventBridge:AccessDeniedException"

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
    placeOrderDenied(orderId: ID!, tier: String!, resource: String!): PutEventsResult
}
"""

# One resolver body for both fields: the ONLY difference between the two paths is the data
# source's service role, so the denial can only come from that role's missing permission.
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


def _mutation(field: str) -> str:
    return (
        "mutation($o: ID!, $t: String!, $r: String!) "
        f"{{ {field}(orderId: $o, tier: $t, resource: $r) {{ failedCount eventIds }} }}"
    )


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
    """A data source whose role lacks events:PutEvents returns AccessDenied and delivers nothing
    while a permitted control is delivered; granting PutEvents makes the same field deliver.
    """
    import requests

    appsync = ctx.client("appsync")
    events = ctx.client("events")
    iam = ctx.client("iam")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    queue_a = _create_queue(ctx)
    _put_rule_with_sqs_target(
        ctx,
        {"source": ["app.orders"], "detail-type": ["OrderPlaced"], "detail": {"tier": ["gold"]}},
        queue_a,
        bus=bus,
    )

    denied_role, denied_arn = _create_appsync_role(ctx, "events:DescribeEventBus", bus_arn)
    _, allowed_arn = _create_appsync_role(ctx, "events:PutEvents", bus_arn)

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
    for ds_name, role_arn, field in (
        ("sim2real_eb_allowed", allowed_arn, "placeOrder"),
        ("sim2real_eb_denied", denied_arn, "placeOrderDenied"),
    ):
        appsync.create_data_source(
            apiId=api_id,
            name=ds_name,
            type="AMAZON_EVENTBRIDGE",
            serviceRoleArn=role_arn,
            eventBridgeConfig={"eventBusArn": bus_arn},
        )
        appsync.create_resolver(
            apiId=api_id,
            typeName="Mutation",
            fieldName=field,
            dataSourceName=ds_name,
            runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
            code=_RESOLVER_CODE,
        )
    api_key = appsync.create_api_key(apiId=api_id, description="sim2real-xsvc")["apiKey"]["id"]

    def call(field: str, order_id: str) -> dict:
        return _graphql(
            ctx, requests,
            graphql_url,
            api_key,
            _mutation(field),
            {"o": order_id, "t": "gold", "r": api_arn},
        )

    # 1. Positive control first: the permitted path is live end to end.
    warm_ids = _emit_until_delivered(ctx, call, "placeOrder", queue_a["url"])

    # 2. The denied path: same resolver, same bus, a role without events:PutEvents.
    denied_id = f"denied-{uuid.uuid4().hex[:12]}"
    denied = _invoke_ok(ctx, call, "placeOrderDenied", denied_id, accept_denied=True)
    errs = denied.get("errors") or []
    assert errs, (
        f"mutation on a data source whose role lacks events:PutEvents SUCCEEDED (over-permissive): "
        f"{denied!r}"
    )
    assert (denied.get("data") or {}).get("placeOrderDenied") is None, (
        f"denied mutation still returned a result: {denied!r}"
    )
    assert errs[0].get("errorType") == _DENIED_ERROR_TYPE, (
        f"denied mutation errorType was {errs[0].get('errorType')!r}, expected "
        f"{_DENIED_ERROR_TYPE!r}: {errs!r}"
    )
    assert errs[0].get("path") == ["placeOrderDenied"], (
        f"error is not attributed to the denied field: path={errs[0].get('path')!r}"
    )
    assert "events:PutEvents" in (errs[0].get("message") or ""), (
        f"denial does not name the missing events:PutEvents permission: {errs[0].get('message')!r}"
    )

    # 3. Barrier: a permitted order sent AFTER the denied one arrives; the denied one never does.
    barrier_id = f"barrier-{uuid.uuid4().hex[:12]}"
    body = _invoke_ok(ctx, call, "placeOrder", barrier_id)
    assert body["data"]["placeOrder"]["failedCount"] == 0, f"control PutEvents failed: {body!r}"
    got, others = _wait_for(
        ctx, queue_a["url"], lambda b: _order_id(b) == barrier_id, timeout_s=60.0
    )
    assert got, (
        f"{DATAPLANE_MARKER}: control order {barrier_id!r} sent after the denied one never reached "
        "queue A, so the denied order's absence is unprovable"
    )
    trailing = _collect(ctx, queue_a["url"], window_s=10.0)
    seen = [_body(m) for m in others + got + trailing]
    leaked = [b for b in seen if _order_id(b) == denied_id]
    assert leaked == [], (
        f"queue A received the DENIED order {denied_id!r} — the data source role's missing "
        f"events:PutEvents permission was not enforced: {leaked!r}"
    )
    unexpected = [b for b in seen if _order_id(b) not in set(warm_ids) | {barrier_id}]
    assert unexpected == [], f"queue A received events nobody sent: {unexpected!r}"

    # 4. Repair the ONE broken thing and require the SAME field to deliver to the SAME queue.
    iam.put_role_policy(
        RoleName=denied_role,
        PolicyName="eventbridge-repair",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn}],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=denied_role, PolicyName="eventbridge-repair")
    )
    repaired_id = f"repaired-{uuid.uuid4().hex[:12]}"
    repaired = _invoke_ok(ctx, call, "placeOrderDenied", repaired_id, timeout_s=120.0)
    assert repaired["data"]["placeOrderDenied"]["failedCount"] == 0, (
        f"repaired data source PutEvents reported a failure: {repaired!r}"
    )
    got, _ = _wait_for(
        ctx, queue_a["url"], lambda b: _order_id(b) == repaired_id, timeout_s=60.0
    )
    assert got, (
        f"after granting events:PutEvents the previously denied field succeeded but order "
        f"{repaired_id!r} never reached queue A"
    )
    env = _body(got[0])
    assert env.get("id") == repaired["data"]["placeOrderDenied"]["eventIds"][0], (
        f"delivered envelope id {env.get('id')!r} is not the EventId AppSync returned "
        f"{repaired['data']['placeOrderDenied']['eventIds']!r}"
    )


# ===== helpers =====
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


def _create_appsync_role(ctx, action: str, bus_arn: str) -> tuple[str, str]:
    """An IAM role AppSync can assume, whose ONLY inline permission is `action` on the bus.
    Returns (name, arn)."""
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
    return name, arn


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


def _invoke_ok(ctx, call, field: str, order_id: str, timeout_s: float = 50.0,
               accept_denied: bool = False) -> dict:
    """Invoke `field`, retrying ONLY the IAM-propagation refusals (role not yet assumable, and
    AccessDenied unless `accept_denied` returns it), until it succeeds."""
    body: dict = {}
    deadline = time.monotonic() + timeout_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        body = call(field, order_id)
        errs = body.get("errors") or []
        if not errs:
            assert (body.get("data") or {}).get(field) is not None, (
                f"mutation returned neither errors nor data: {body!r}"
            )
            return body
        if accept_denied and errs[0].get("errorType") == _DENIED_ERROR_TYPE:
            return body
        if errs[0].get("errorType") != _DENIED_ERROR_TYPE and not _assume_pending(errs[0]):
            raise AssertionError(f"{field} for {order_id!r} failed unexpectedly: {errs!r}")
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    raise AssertionError(
        f"data source role for {field} never became usable for PutEvents (IAM propagation): {body!r}"
    )


def _assume_pending(err: dict) -> bool:
    """AppSync's IAM-propagation refusal while a just-created data source role is not yet assumable."""
    return err.get("errorType") == "Unauthorized" and "Unable to assume role" in (err.get("message") or "")


def _emit_until_delivered(ctx, call, field: str, queue_url: str, attempts: int = 8) -> list[str]:
    """Send fresh gold orders through `field` until one lands on queue_url; return every id sent."""
    sent: list[str] = []
    for _ in range(attempts):
        oid = f"warm-{uuid.uuid4().hex[:12]}"
        _invoke_ok(ctx, call, field, oid)
        sent.append(oid)
        got, _ = _wait_for(ctx, queue_url, lambda b: _order_id(b) in sent, timeout_s=12.0)
        if got:
            return sent
    raise AssertionError(
        f"{DATAPLANE_MARKER}: positive control failed — no order sent through the permitted "
        f"AppSync EventBridge data source reached {queue_url} after {attempts} attempts ({sent!r})"
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
    """Drain a queue over a bounded window with long-polling ReceiveMessage and return EVERY
    message seen (deleting each). An empty return is only meaningful once a positive delivery has
    already been observed elsewhere in the check."""
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
