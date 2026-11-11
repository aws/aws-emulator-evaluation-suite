"""eventbridge-datasource-role-scoped-to-other-bus-denied."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-datasource-role-scoped-to-other-bus-denied"
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
    placeOnX(orderId: ID!): PutEventsResult
    placeOnY(orderId: ID!): PutEventsResult
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
    "axis:rejection",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A role allowed PutEvents on bus X only: its data source on bus Y gets AccessDenied and
    delivers nothing while bus X delivers; adding bus Y to the policy makes the same field deliver.
    """
    import requests

    appsync = ctx.client("appsync")
    events = ctx.client("events")
    iam = ctx.client("iam")

    buses = {}
    for key in ("x", "y"):
        name = _xname(ctx, "bus")
        arn = events.create_event_bus(Name=name, Tags=_xsvc_tags_kv())["EventBusArn"]
        ctx.on_cleanup(lambda n=name: events.delete_event_bus(Name=n))
        q = _create_queue(ctx)
        _put_rule_with_sqs_target(ctx, {"detail": {"tier": ["gold"]}}, q, bus=name)
        buses[key] = {"name": name, "arn": arn, "queue": q}

    role_name, role_arn = _create_appsync_role_scoped(ctx, [buses["x"]["arn"]])

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
    for key, field in (("x", "placeOnX"), ("y", "placeOnY")):
        ds_name = f"sim2real_eb_bus_{key}"
        appsync.create_data_source(
            apiId=api_id,
            name=ds_name,
            type="AMAZON_EVENTBRIDGE",
            serviceRoleArn=role_arn,
            eventBridgeConfig={"eventBusArn": buses[key]["arn"]},
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

    def call(field: str, oid: str) -> dict:
        return _graphql(ctx, requests, graphql_url, api_key, _mutation(field), {"o": oid})

    def place_ok(field: str, prefix: str, timeout_s: float = 50.0) -> tuple[str, dict]:
        oid = f"{prefix}-{uuid.uuid4().hex[:12]}"
        body = _invoke_ok(
            ctx, requests, graphql_url, api_key, field, _mutation(field), {"o": oid}, timeout_s=timeout_s
        )
        resp = body["data"][field]
        assert resp["failedCount"] == 0, f"{field} PutEvents reported a failure: {body!r}"
        return oid, resp

    qx, qy = buses["x"]["queue"]["url"], buses["y"]["queue"]["url"]
    seen_x: list = []
    seen_y: list = []

    # 1. Bus X path is live.
    sent_x: list[str] = []
    for _ in range(8):
        oid, _ = place_ok("placeOnX", "x-warm")
        sent_x.append(oid)
        seen_x += [_body(m) for m in _collect(ctx, qx, window_s=12.0)]
        if any(_order_id(b) in sent_x for b in seen_x):
            break
    assert any(_order_id(b) in sent_x for b in seen_x), (
        f"{DATAPLANE_MARKER}: no order through the bus-X data source reached queue X ({sent_x!r})"
    )

    # 2. Same role, bus Y: denied on the resource.
    denied_id = f"y-denied-{uuid.uuid4().hex[:12]}"
    denied = call("placeOnY", denied_id)
    errs = denied.get("errors") or []
    assert errs, (
        f"data source on bus Y SUCCEEDED with a role scoped to bus X only (over-permissive): "
        f"{denied!r}"
    )
    assert (denied.get("data") or {}).get("placeOnY") is None, (
        f"denied mutation still returned a result: {denied!r}"
    )
    assert errs[0].get("errorType") == _DENIED_ERROR_TYPE, (
        f"errorType was {errs[0].get('errorType')!r}, expected {_DENIED_ERROR_TYPE!r}: {errs!r}"
    )
    assert buses["y"]["arn"] in (errs[0].get("message") or ""), (
        f"denial does not name bus Y {buses['y']['arn']!r}: {errs[0].get('message')!r}"
    )

    # 3. Barrier on X, then Y must hold nothing.
    barrier, _ = place_ok("placeOnX", "x-barrier")
    sent_x.append(barrier)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not any(_order_id(b) == barrier for b in seen_x):
        seen_x += [_body(m) for m in _collect(ctx, qx, window_s=6.0)]
    assert any(_order_id(b) == barrier for b in seen_x), (
        f"{DATAPLANE_MARKER}: control {barrier!r} sent after the denial never reached queue X, so "
        "queue Y's silence is unprovable"
    )
    seen_y += [_body(m) for m in _collect(ctx, qy, window_s=10.0)]
    assert seen_y == [], (
        f"queue Y received events although the only data source targeting bus Y was denied: "
        f"{seen_y!r}"
    )
    stray_x = [b for b in seen_x if _order_id(b) not in sent_x]
    assert stray_x == [], f"queue X received events nobody sent to bus X: {stray_x!r}"

    # 4. Repair the resource scope; the SAME field must now deliver to queue Y.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="eventbridge",
        PolicyDocument=json.dumps(_put_events_policy([buses["x"]["arn"], buses["y"]["arn"]])),
    )
    repaired, resp = place_ok("placeOnY", "y-repaired", timeout_s=120.0)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not any(_order_id(b) == repaired for b in seen_y):
        seen_y += [_body(m) for m in _collect(ctx, qy, window_s=6.0)]
    hit = [b for b in seen_y if _order_id(b) == repaired]
    assert hit, f"after widening the role to bus Y, order {repaired!r} never reached queue Y"
    assert hit[0].get("id") == resp["eventIds"][0], (
        f"queue Y envelope id {hit[0].get('id')!r} is not the EventId AppSync returned "
        f"{resp['eventIds']!r}"
    )
    assert not any(_order_id(b) == denied_id for b in seen_x + seen_y), (
        f"the denied order {denied_id!r} was delivered after all"
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


def _put_events_policy(bus_arns: list[str]) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arns}],
    }


def _create_appsync_role_scoped(ctx, bus_arns: list[str]) -> tuple[str, str]:
    """An IAM role AppSync can assume, allowed events:PutEvents on exactly `bus_arns`.
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
        PolicyDocument=json.dumps(_put_events_policy(bus_arns)),
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
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: GraphQL endpoint {url!r} unreachable: {type(exc).__name__}: {exc}"
        ) from exc
    assert r.status_code == 200, (
        f"{DATAPLANE_MARKER}: GraphQL endpoint returned HTTP {r.status_code}: {r.text[:400]!r}"
    )
    return r.json()


def _invoke_ok(ctx, requests, url, api_key, field, query, variables, timeout_s=50.0) -> dict:
    """Invoke the mutation, retrying ONLY the IAM-propagation refusals (role not yet assumable,
    AccessDenied), until it succeeds."""
    body: dict = {}
    deadline = time.monotonic() + timeout_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        body = _graphql(ctx, requests, url, api_key, query, variables)
        errs = body.get("errors") or []
        if not errs:
            assert (body.get("data") or {}).get(field) is not None, (
                f"mutation returned neither errors nor data: {body!r}"
            )
            return body
        if errs[0].get("errorType") != "EventBridge:AccessDeniedException" and not _assume_pending(errs[0]):
            raise AssertionError(f"{field} failed unexpectedly: {errs!r}")
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    raise AssertionError(
        f"data source role never became usable for PutEvents (IAM propagation): {body!r}"
    )


def _assume_pending(err: dict) -> bool:
    """AppSync's IAM-propagation refusal while a just-created data source role is not yet assumable."""
    return err.get("errorType") == "Unauthorized" and "Unable to assume role" in (err.get("message") or "")


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
