"""eventbridge-datasource-batch-entries-route-independently-in-order."""

from __future__ import annotations

import datetime
import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-datasource-batch-entries-route-independently-in-order"
GROUP = "event-propagation"
SERVICES = ["appsync", "events", "sqs"]

# Marks a missing endpoint data plane, so it is reported as a failure.
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
    placePair(goldId: ID!, silverId: ID!, goldTime: String!): PutEventsResult
}
"""

# ONE resolver invocation, ONE PutEvents call carrying TWO entries: entry 0 is a gold order with an
# explicit `time`, entry 1 a silver order with none.
_RESOLVER_CODE = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'PutEvents',
    events: [
      { source: 'app.orders', detailType: 'OrderPlaced',
        detail: { orderId: ctx.args.goldId, tier: 'gold' }, time: ctx.args.goldTime },
      { source: 'app.orders', detailType: 'OrderPlaced',
        detail: { orderId: ctx.args.silverId, tier: 'silver' } },
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
    "mutation($g: ID!, $s: ID!, $t: String!) "
    "{ placePair(goldId: $g, silverId: $s, goldTime: $t) { failedCount eventIds } }"
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
    """Two entries in one AppSync-issued PutEvents route independently to their own rule's queue,
    eventIds keep entry order, and entry 0's explicit `time` survives while entry 1 gets none.
    """
    import requests

    appsync = ctx.client("appsync")
    events = ctx.client("events")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    queue_gold = _create_queue(ctx)
    queue_silver = _create_queue(ctx)
    _put_rule_with_sqs_target(ctx, {"detail": {"tier": ["gold"]}}, queue_gold, bus=bus)
    _put_rule_with_sqs_target(ctx, {"detail": {"tier": ["silver"]}}, queue_silver, bus=bus)

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

    # A whole-second UTC instant an hour in the past: distinct from the delivery time EventBridge
    # would stamp on its own, so "preserved" and "defaulted" cannot coincide.
    gold_time = (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        - datetime.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    sent_gold: set[str] = set()
    sent_silver: set[str] = set()
    seen_gold_q: list[dict] = []
    seen_silver_q: list[dict] = []
    result = None
    # Fresh orderIds per attempt: a new rule that drops an early event costs a retry, not a copy.
    for _ in range(6):
        gid = f"gold-{uuid.uuid4().hex[:12]}"
        sid = f"silver-{uuid.uuid4().hex[:12]}"
        body = _invoke_ok(
            ctx, requests, graphql_url, api_key, "placePair", _MUTATION,
            {"g": gid, "s": sid, "t": gold_time},
        )
        sent_gold.add(gid)
        sent_silver.add(sid)
        resp = body["data"]["placePair"]
        assert resp["failedCount"] == 0, f"PutEvents via AppSync reported a failure: {body!r}"
        assert len(resp["eventIds"]) == 2 and len(set(resp["eventIds"])) == 2, (
            f"two entries were sent but PutEvents returned eventIds={resp['eventIds']!r}"
        )
        g_got, g_other = _wait_for(
            ctx, queue_gold["url"], lambda b, o=gid: _order_id(b) == o, timeout_s=12.0
        )
        s_got, s_other = _wait_for(
            ctx, queue_silver["url"], lambda b, o=sid: _order_id(b) == o, timeout_s=12.0
        )
        seen_gold_q += [_body(m) for m in g_got + g_other]
        seen_silver_q += [_body(m) for m in s_got + s_other]
        if g_got and s_got:
            result = {"gold": _body(g_got[0]), "silver": _body(s_got[0]), "resp": resp}
            break
    if result is None and _budget_spent(ctx):
        raise TimeoutError(
            "both entries of a pair delivered to their queues: the run budget ended first; "
            "not graded"
        )
    if result is None:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: no pair sent through the AppSync EventBridge data source had both "
            f"entries delivered (gold ids {sorted(sent_gold)!r}, silver ids {sorted(sent_silver)!r})"
        )

    gold_env, silver_env, resp = result["gold"], result["silver"], result["resp"]
    assert gold_env.get("id") == resp["eventIds"][0], (
        f"eventIds[0] {resp['eventIds'][0]!r} is not the gold (entry 0) envelope id "
        f"{gold_env.get('id')!r}; eventIds={resp['eventIds']!r}"
    )
    assert silver_env.get("id") == resp["eventIds"][1], (
        f"eventIds[1] {resp['eventIds'][1]!r} is not the silver (entry 1) envelope id "
        f"{silver_env.get('id')!r}; eventIds={resp['eventIds']!r}"
    )
    assert gold_env.get("time") == gold_time, (
        f"entry 0 set time {gold_time!r} but the delivered envelope has {gold_env.get('time')!r}"
    )
    assert silver_env.get("time") != gold_time, (
        f"entry 1 set no time yet was delivered with entry 0's time {gold_time!r}"
    )
    assert gold_env.get("detail", {}).get("tier") == "gold", gold_env
    assert silver_env.get("detail", {}).get("tier") == "silver", silver_env

    # Independent routing: after both legs delivered, drain once more and require that no silver
    # entry ever reached the gold queue and no gold entry ever reached the silver queue.
    seen_gold_q += [_body(m) for m in _collect(ctx, queue_gold["url"], window_s=3.0)]
    seen_silver_q += [_body(m) for m in _collect(ctx, queue_silver["url"], window_s=3.0)]
    wrong_in_gold = [b for b in seen_gold_q if _order_id(b) not in sent_gold]
    wrong_in_silver = [b for b in seen_silver_q if _order_id(b) not in sent_silver]
    assert wrong_in_gold == [], (
        f"the gold rule's queue received non-gold entries — the batch was not routed per entry: "
        f"{wrong_in_gold!r}"
    )
    assert wrong_in_silver == [], (
        f"the silver rule's queue received non-silver entries — the batch was not routed per "
        f"entry: {wrong_in_silver!r}"
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
    # IAM propagation exposes no condition to poll; the bounded retry of the propagation
    # refusals at first use (_invoke_ok) absorbs it.
    return arn


def _graphql(ctx, requests, url: str, api_key: str, query: str, variables: dict) -> dict:
    """POST one GraphQL operation over the live endpoint; a transport failure fails the check."""
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


def _invoke_ok(ctx, requests, url, api_key, field, query, variables, timeout_s=60.0) -> dict:
    """Invoke the mutation, retrying ONLY the IAM-propagation refusals (AppSync cannot yet assume
    the data source role, or the role cannot yet PutEvents), until it succeeds."""
    body: dict = {}
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        body = _graphql(ctx, requests, url, api_key, query, variables)
        errs = body.get("errors") or []
        if not errs:
            assert (body.get("data") or {}).get(field) is not None, (
                f"mutation returned neither errors nor data: {body!r}"
            )
            return body
        if not _iam_propagating(errs[0]):
            raise AssertionError(f"{field} failed unexpectedly: {errs!r}")
        if time.monotonic() + 1.5 >= deadline:
            break
        time.sleep(1.5)
    if _budget_spent(ctx):
        raise TimeoutError(
            "the data source role becoming usable for PutEvents: the run budget ended first; "
            "not graded"
        )
    raise AssertionError(
        f"data source role never became usable for PutEvents (IAM propagation): {body!r}"
    )


def _iam_propagating(err: dict) -> bool:
    if err.get("errorType") == "EventBridge:AccessDeniedException":
        return True
    return err.get("errorType") == "Unauthorized" and str(err.get("message", "")).startswith(
        "Unable to assume role "
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline and not matched:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            (matched if predicate(_body(msg)) else others).append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
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
