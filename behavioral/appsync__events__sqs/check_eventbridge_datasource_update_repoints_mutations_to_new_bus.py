"""eventbridge-datasource-update-repoints-mutations-to-new-bus."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-datasource-update-repoints-mutations-to-new-bus"
GROUP = "event-propagation"
SERVICES = ["appsync", "events", "sqs"]

# Marks a failure as an unimplemented data plane rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

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
    placeOrder(orderId: ID!): PutEventsResult
}
"""

_RESOLVER_CODE = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'PutEvents',
    events: [{
      source: 'app.orders',
      detailType: 'OrderPlaced',
      detail: { orderId: ctx.args.orderId, tier: 'gold' },
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
    return f"mutation($o: ID!) {{ {field}(orderId: $o) {{ failedCount eventIds }} }}"


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
    """UpdateDataSource repointing eventBusArn moves the same mutation's PutEvents to the new bus.

    After the update, orders land on bus 2's queue (polled) and a fresh order never reaches bus 1.
    """
    import requests

    appsync = ctx.client("appsync")
    events = ctx.client("events")

    buses = []
    for _ in range(2):
        name = _xname(ctx, "bus")
        arn = events.create_event_bus(Name=name, Tags=_xsvc_tags_kv())["EventBusArn"]
        ctx.on_cleanup(lambda n=name: events.delete_event_bus(Name=n))
        q = _create_queue(ctx)
        _put_rule_with_sqs_target(ctx, {"detail": {"tier": ["gold"]}}, q, bus=name)
        buses.append({"name": name, "arn": arn, "queue": q})
    bus1, bus2 = buses

    role_arn = _create_appsync_role_multi(ctx, [bus1["arn"], bus2["arn"]])

    api = appsync.create_graphql_api(
        name=_xname(ctx, "api"),
        authenticationType="API_KEY",
        tags=_xsvc_resource_tags(),
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    graphql_url = api.get("uris", {}).get("GRAPHQL")
    assert graphql_url, f"GraphQL API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"

    _create_schema(appsync, api_id, _SCHEMA)
    ds_name = "sim2real_eb_repoint"
    appsync.create_data_source(
        apiId=api_id,
        name=ds_name,
        type="AMAZON_EVENTBRIDGE",
        serviceRoleArn=role_arn,
        eventBridgeConfig={"eventBusArn": bus1["arn"]},
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Mutation",
        fieldName="placeOrder",
        dataSourceName=ds_name,
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=_RESOLVER_CODE,
    )
    api_key = appsync.create_api_key(apiId=api_id, description="sim2real-xsvc")["apiKey"]["id"]

    sent: list[str] = []

    def place(prefix: str) -> tuple[str, dict]:
        oid = f"{prefix}-{uuid.uuid4().hex[:12]}"
        body = _invoke_ok(
            ctx, requests, graphql_url, api_key, "placeOrder", _mutation("placeOrder"), {"o": oid}
        )
        sent.append(oid)
        resp = body["data"]["placeOrder"]
        assert resp["failedCount"] == 0, f"PutEvents via AppSync reported a failure: {body!r}"
        return oid, resp

    seen = {"q1": [], "q2": []}

    def drain(which: str, window_s: float) -> None:
        q = bus1["queue"] if which == "q1" else bus2["queue"]
        seen[which] += [_body(m) for m in _collect(ctx, q["url"], window_s=window_s)]

    def arrived(which: str, oid: str) -> bool:
        return any(_order_id(b) == oid for b in seen[which])

    # 1. Bound to bus 1: an order reaches queue 1.
    first = None
    for _ in range(8):
        oid, _ = place("bus1")
        drain("q1", 12.0)
        hit = [o for o in sent if arrived("q1", o)]
        if hit:
            first = hit[0]
            break
    assert first is not None, (
        f"{DATAPLANE_MARKER}: no order sent through the AppSync EventBridge data source reached "
        f"bus 1's queue ({sent!r})"
    )
    bus1_ids = list(sent)

    # 2. Repoint the data source.
    updated = appsync.update_data_source(
        apiId=api_id,
        name=ds_name,
        type="AMAZON_EVENTBRIDGE",
        serviceRoleArn=role_arn,
        eventBridgeConfig={"eventBusArn": bus2["arn"]},
    )["dataSource"]
    assert updated["eventBridgeConfig"]["eventBusArn"] == bus2["arn"], (
        f"UpdateDataSource returned {updated.get('eventBridgeConfig')!r}, expected {bus2['arn']!r}"
    )
    read = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert read["eventBridgeConfig"]["eventBusArn"] == bus2["arn"], (
        f"GetDataSource after update reads {read.get('eventBridgeConfig')!r}, expected {bus2['arn']!r}"
    )

    # 3. The data plane follows the update: poll, as the update may take a moment to propagate.
    post_update: list[str] = []
    on_bus2 = None
    for _ in range(12):
        oid, _ = place("after")
        post_update.append(oid)
        drain("q2", 10.0)
        hit = [o for o in post_update if arrived("q2", o)]
        if hit:
            on_bus2 = hit[0]
            break
    assert on_bus2 is not None, (
        f"after UpdateDataSource to bus 2, none of {post_update!r} reached bus 2's queue — the "
        "data plane did not follow the data source update"
    )

    # 4. Steady state: a fresh order lands on queue 2 and never on queue 1.
    final, resp = place("final")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not arrived("q2", final):
        drain("q2", 6.0)
    assert arrived("q2", final), f"post-update order {final!r} never reached bus 2's queue"
    env = next(b for b in seen["q2"] if _order_id(b) == final)
    assert env.get("id") == resp["eventIds"][0], (
        f"bus-2 envelope id {env.get('id')!r} is not the EventId AppSync returned {resp['eventIds']!r}"
    )
    drain("q1", 15.0)
    assert not arrived("q1", final), (
        f"order {final!r} sent after the repoint AND after bus 2 was confirmed still reached bus "
        f"1's queue: {[b for b in seen['q1'] if _order_id(b) == final]!r}"
    )
    stray = [b for b in seen["q2"] if _order_id(b) in bus1_ids]
    assert stray == [], f"orders sent BEFORE the update reached bus 2: {stray!r}"


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


def _create_appsync_role_multi(ctx, bus_arns: list[str]) -> str:
    """An IAM role AppSync can assume, allowed events:PutEvents on exactly `bus_arns`."""
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
                "Statement": [
                    {"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arns}
                ],
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
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: GraphQL endpoint {url!r} unreachable: {type(exc).__name__}: {exc}"
        ) from exc
    assert r.status_code == 200, (
        f"{DATAPLANE_MARKER}: GraphQL endpoint returned HTTP {r.status_code}: {r.text[:400]!r}"
    )
    return r.json()


def _is_iam_propagation_error(err: dict) -> bool:
    """True for the two shapes AppSync returns while a freshly created role has not yet
    propagated: the trust policy not yet visible (Unauthorized, "Unable to assume role") and
    the permission policy not yet visible (EventBridge:AccessDeniedException)."""
    error_type = err.get("errorType")
    if error_type == "EventBridge:AccessDeniedException":
        return True
    return error_type == "Unauthorized" and "Unable to assume role" in (err.get("message") or "")


def _invoke_ok(ctx, requests, url, api_key, field, query, variables, timeout_s=60.0) -> dict:
    """Invoke the mutation, retrying ONLY the IAM-propagation errors every 2 s until it
    succeeds; the deadline is capped by the run budget."""
    body: dict = {}
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        body = _graphql(ctx, requests, url, api_key, query, variables)
        errs = body.get("errors") or []
        if not errs:
            assert (body.get("data") or {}).get(field) is not None, (
                f"mutation returned neither errors nor data: {body!r}"
            )
            return body
        if not _is_iam_propagation_error(errs[0]):
            raise AssertionError(f"{field} failed unexpectedly: {errs!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"data source role never became usable for PutEvents (IAM propagation): {body!r}"
            )
        time.sleep(2)


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
