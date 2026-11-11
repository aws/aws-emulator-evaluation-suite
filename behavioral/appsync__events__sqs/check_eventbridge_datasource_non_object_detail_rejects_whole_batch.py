"""eventbridge-datasource-non-object-detail-rejects-whole-batch."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-datasource-non-object-detail-rejects-whole-batch"
GROUP = "error-propagation"
SERVICES = ["appsync", "events", "sqs"]

# Marks a missing endpoint data plane, so it is reported as a failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Observed on real AWS: AppSync's own request validation, raised before EventBridge is called.
_INVALID_DETAIL_ERROR_TYPE = "Code"

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
    placePair(firstId: ID!, secondId: ID!, bad: Boolean!): PutEventsResult
}
"""

# Two gold entries in one PutEvents. With bad=true ONLY entry 1's detail changes — to a bare
# string, which is not a JSON object. Entry 0 is identical in both modes.
_RESOLVER_CODE = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  const second = ctx.args.bad
    ? 'not-an-object'
    : { orderId: ctx.args.secondId, tier: 'gold' };
  return {
    operation: 'PutEvents',
    events: [
      { source: 'app.orders', detailType: 'OrderPlaced',
        detail: { orderId: ctx.args.firstId, tier: 'gold' } },
      { source: 'app.orders', detailType: 'OrderPlaced', detail: second },
    ],
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
    "mutation($a: ID!, $b: ID!, $bad: Boolean!) "
    "{ placePair(firstId: $a, secondId: $b, bad: $bad) { failedCount eventIds } }"
)


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
    """A resolver PutEvents batch with one non-object detail fails whole with a GraphQL error and
    emits no entry, while a valid control pair sent after it is delivered.
    """
    import requests

    appsync = ctx.client("appsync")
    events = ctx.client("events")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    queue = _create_queue(ctx)
    _put_rule_with_sqs_target(ctx, {"detail": {"tier": ["gold"]}}, queue, bus=bus)
    role_arn = _create_appsync_role(ctx, "events:PutEvents", bus_arn)

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
    ds = appsync.create_data_source(
        apiId=api_id,
        name="sim2real_eb_pairs",
        type="AMAZON_EVENTBRIDGE",
        serviceRoleArn=role_arn,
        eventBridgeConfig={"eventBusArn": bus_arn},
    )["dataSource"]
    appsync.create_resolver(
        apiId=api_id,
        typeName="Mutation",
        fieldName="placePair",
        dataSourceName=ds["name"],
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=_RESOLVER_CODE,
    )
    api_key = appsync.create_api_key(apiId=api_id, description="sim2real-xsvc")["apiKey"]["id"]

    sent_ok: set[str] = set()
    seen: list[dict] = []

    def send_valid_pair(prefix: str) -> tuple[str, str, dict]:
        a, b = f"{prefix}-a-{uuid.uuid4().hex[:10]}", f"{prefix}-b-{uuid.uuid4().hex[:10]}"
        body = _invoke_ok(
            ctx, requests, graphql_url, api_key, "placePair", _MUTATION, {"a": a, "b": b, "bad": False}
        )
        sent_ok.update({a, b})
        resp = body["data"]["placePair"]
        assert resp["failedCount"] == 0 and len(resp["eventIds"]) == 2, (
            f"valid pair did not report two accepted entries: {body!r}"
        )
        return a, b, resp

    # 1. The path is live: a valid pair's first entry reaches the queue.
    live = False
    for _ in range(8):
        a, _b, _ = send_valid_pair("warm")
        got, other = _wait_for(ctx, queue["url"], lambda x: _order_id(x) in sent_ok, timeout_s=12.0)
        seen += [_body(m) for m in got + other]
        if got:
            live = True
            break
    assert live, (
        f"{DATAPLANE_MARKER}: no valid pair sent through the AppSync EventBridge data source "
        f"reached the queue ({sorted(sent_ok)!r})"
    )

    # 2. The bad pair: entry 0 valid, entry 1's detail a bare string.
    bad_a, bad_b = f"bad-a-{uuid.uuid4().hex[:10]}", f"bad-b-{uuid.uuid4().hex[:10]}"
    bad = _graphql(
        ctx, requests, graphql_url, api_key, _MUTATION, {"a": bad_a, "b": bad_b, "bad": True}
    )
    errs = bad.get("errors") or []
    assert errs, f"a PutEvents batch with a non-object detail SUCCEEDED via AppSync: {bad!r}"
    assert (bad.get("data") or {}).get("placePair") is None, (
        f"rejected batch still returned a result: {bad!r}"
    )
    assert errs[0].get("errorType") == _INVALID_DETAIL_ERROR_TYPE, (
        f"errorType was {errs[0].get('errorType')!r}, expected {_INVALID_DETAIL_ERROR_TYPE!r}: "
        f"{errs!r}"
    )
    msg = errs[0].get("message") or ""
    assert "[events][1][detail]" in msg, (
        f"error does not locate the offending entry 1 detail: {msg!r}"
    )

    # 3. Barrier: a valid control pair sent AFTER the bad one arrives in full; the bad call's
    #    VALID entry 0 must never have been emitted.
    ca, cb, _ = send_valid_pair("ctl")
    found, drained = _wait_for_all(ctx, queue["url"], {ca, cb}, timeout_s=60.0)
    seen += drained
    assert set(found) == {ca, cb}, (
        f"{DATAPLANE_MARKER}: control entries {sorted({ca, cb} - set(found))!r} sent after the "
        "rejected batch never arrived, so the rejected entries' absence is unprovable"
    )
    seen += [_body(m) for m in _collect(ctx, queue["url"], window_s=10.0)]
    leaked = [b for b in seen if _order_id(b) in (bad_a, bad_b)]
    assert leaked == [], (
        f"entries of the REJECTED batch were delivered — AppSync forwarded a batch it reported as "
        f"failed: {leaked!r}"
    )
    unexpected = [b for b in seen if _order_id(b) not in sent_ok]
    assert unexpected == [], f"queue received events nobody sent: {unexpected!r}"

    # 4. Repair the one broken thing (bad=false) on the SAME field: both entries arrive.
    ra, rb, resp = send_valid_pair("repaired")
    delivered, _ = _wait_for_all(ctx, queue["url"], {ra, rb}, timeout_s=60.0)
    assert set(delivered) == {ra, rb}, (
        f"repaired pair entries {sorted({ra, rb} - set(delivered))!r} never reached the queue"
    )
    assert [delivered[ra].get("id"), delivered[rb].get("id")] == resp["eventIds"], (
        f"repaired pair envelope ids {[delivered[ra].get('id'), delivered[rb].get('id')]!r} are not "
        f"the eventIds AppSync returned {resp['eventIds']!r}"
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
    """AppSync's IAM-propagation refusals for a just-created data source role: not yet assumable,
    or its session token not yet accepted by EventBridge."""
    message = err.get("message") or ""
    if err.get("errorType") == "EventBridge:EventBridgeException":
        return "The security token included in the request is invalid" in message
    return err.get("errorType") == "Unauthorized" and "Unable to assume role" in message


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


def _wait_for_all(ctx, queue_url, order_ids, *, timeout_s=60.0):
    """Drain a queue until every orderId in `order_ids` has been seen at least once.
    Returns ({orderId: first envelope}, every parsed body drained) — siblings that arrive in the
    same receive are kept, never lost to a one-id-at-a-time wait."""
    found: dict[str, Any] = {}
    drained: list[Any] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and set(found) != set(order_ids):
        for msg in _collect(ctx, queue_url, window_s=6.0):
            b = _body(msg)
            drained.append(b)
            if _order_id(b) in order_ids:
                found.setdefault(_order_id(b), b)
    return found, drained


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
