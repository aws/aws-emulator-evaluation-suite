"""xsvc-appsync-2-role-without-graphql-denied-dead-letters-and-counts-failed-invocations."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-appsync-2-role-without-graphql-denied-dead-letters-and-counts-failed-invocations"
GROUP = "permission-chain"
SERVICES = ["appsync", "dynamodb", "events"]

_SOURCE = "app.ingest"
_DETAIL_TYPE = "ItemArrived"

_SDL = """schema { query: Query mutation: Mutation }
type Item {
    id: ID!
    kind: String!
}
type Query {
    getItem(id: ID!): Item
}
type Mutation {
    putItem(id: ID!, kind: String!): Item
}
"""

_PUT_REQUEST = (
    '{"version": "2018-05-29", "operation": "PutItem", '
    '"key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)}, '
    '"attributeValues": {"kind": $util.dynamodb.toDynamoDBJson($ctx.args.kind)}}'
)
_PASSTHROUGH_RESPONSE = "$util.toJson($ctx.result)"

_MUTATION = "mutation PutItem($id: ID!, $kind: String!) { putItem(id: $id, kind: $kind) { id kind } }"

# DLQ codes a brand-new role produces while IAM propagates — retried on the HEALTHY leg only.
_PROPAGATION_CODES = frozenset({"FAILED_TO_ASSUME_ROLE", "NO_PERMISSIONS"})


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded wait that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _delete_role(iam, name):
    for pol in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=pol)
    iam.delete_role(RoleName=name)


def _put_policy(ctx, name, statements):
    ctx.client("iam").put_role_policy(
        RoleName=name,
        PolicyName="sim2real-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _create_role(ctx, name, trusted_service):
    arn = ctx.client("iam").create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(trusted_service),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx.client("iam"), name))
    return arn


def _create_table(ctx, name):
    ddb = ctx.client("dynamodb")
    arn = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=2,
        description=f"DynamoDB table {name} reaching ACTIVE",
    )
    return arn


def _create_api(ctx, name, ds_role_arn, table):
    """AWS_IAM GraphQL API whose Mutation.putItem is a VTL PutItem into `table`.
    Returns (api_id, graphql_uri)."""
    ap = ctx.client("appsync")
    api = ap.create_graphql_api(
        name=name, authenticationType="AWS_IAM", tags={"sim2real": CHECK}
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: ctx.client("appsync").delete_graphql_api(apiId=api_id))
    ap.start_schema_creation(apiId=api_id, definition=_SDL.encode("utf-8"))
    status = _poll_until(
        lambda: ap.get_schema_creation_status(apiId=api_id)["status"],
        lambda s: s not in ("PROCESSING", "NOT_APPLICABLE"),
        timeout_s=120,
        interval_s=2,
        description=f"schema creation on {api_id} leaving PROCESSING",
    )
    assert status == "SUCCESS", f"schema creation on {api_id} ended {status!r}, expected 'SUCCESS'"
    ap.create_data_source(
        apiId=api_id,
        name="items",
        type="AMAZON_DYNAMODB",
        serviceRoleArn=ds_role_arn,
        dynamodbConfig={"tableName": table, "awsRegion": ctx.region},
    )
    ctx.on_cleanup(lambda: ctx.client("appsync").delete_data_source(apiId=api_id, name="items"))
    ap.create_resolver(
        apiId=api_id,
        typeName="Mutation",
        fieldName="putItem",
        dataSourceName="items",
        requestMappingTemplate=_PUT_REQUEST,
        responseMappingTemplate=_PASSTHROUGH_RESPONSE,
    )
    ctx.on_cleanup(
        lambda: ctx.client("appsync").delete_resolver(
            apiId=api_id, typeName="Mutation", fieldName="putItem"
        )
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL URI: {api.get('uris')!r}"
    # Graded by scheme family and host; a target served over TLS publishes https.
    assert not (p := ctx.published_url_mismatch(uri)), p
    assert uri.startswith("https://") or not ap.meta.endpoint_url.startswith("https://"), (
        f"the API exposed no GRAPHQL https URI: {api.get('uris')!r}"
    )
    return api_id, uri


def _signed_graphql(ctx, uri, query, variables):
    """SigV4-signed POST to the GraphQL endpoint with the LEASED keys -> (status, body)."""
    env = ctx.subprocess_env()
    assert env.get("AWS_ACCESS_KEY_ID"), "ctx.subprocess_env() exposes no signing credentials"
    creds = Credentials(env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"], env.get("AWS_SESSION_TOKEN"))
    body = json.dumps({"query": query, "variables": variables}).encode()
    req = AWSRequest(method="POST", url=uri, data=body, headers={"Content-Type": "application/json"})
    SigV4Auth(creds, "appsync", ctx.region).add_auth(req)
    routed_url, route_headers = ctx.endpoint_route(uri)
    http = urllib.request.Request(routed_url, data=body, method="POST", headers={**dict(req.headers), **route_headers})
    try:
        with urllib.request.urlopen(http, timeout=30) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _warm_resolver(ctx, uri, item_id):
    """Drive the resolver directly until the data-source role has propagated, so a later absence
    can only be attributed to the EventBridge leg."""
    status, body = _poll_until(
        lambda: _signed_graphql(ctx, uri, _MUTATION, {"id": item_id, "kind": "warm"}),
        lambda r: r[0] == 200 and not r[1].get("errors") and (r[1].get("data") or {}).get("putItem"),
        timeout_s=150,
        interval_s=5,
        description="a signed putItem mutation to resolve (data-source role propagation)",
    )
    assert body["data"]["putItem"] == {"id": item_id, "kind": "warm"}, (
        f"the signed warm-up mutation resolved to {body['data']['putItem']!r}"
    )


def _target_arn(ctx, uri):
    """EventBridge addresses an AppSync target by the GraphQL ENDPOINT id (the host label of the
    GRAPHQL URI), not by the apiId."""
    ident = ctx.client("sts").get_caller_identity()
    partition = ident["Arn"].split(":")[1]
    host_label = uri.split("://", 1)[1].split(".", 1)[0]
    return f"arn:{partition}:appsync:{ctx.region}:{ident['Account']}:endpoints/graphql-api/{host_label}"


def _create_dlq(ctx, name, rule_arn_like):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnLike": {"aws:SourceArn": rule_arn_like}},
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _attr(msg, key):
    return msg.get("MessageAttributes", {}).get(key, {}).get("StringValue")


def _make_rule(ctx, bus, name, pattern, target):
    events = ctx.client("events")
    arn = events.put_rule(
        Name=name,
        EventBusName=bus,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=name, EventBusName=bus))
    put = events.put_targets(Rule=name, EventBusName=bus, Targets=[target])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=name, EventBusName=bus, Ids=[target["Id"]], Force=True
        )
    )
    assert put["FailedEntryCount"] == 0, (
        f"PutTargets on {name} reported FailedEntryCount={put['FailedEntryCount']}: "
        f"{put['FailedEntries']!r} — real AWS accepts this target; the role is only evaluated at delivery"
    )
    return arn


def _fire(ctx, bus, item_id, kind):
    resp = ctx.client("events").put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"id": item_id, "kind": kind}),
            }
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"PutEvents refused the entry: {resp['Entries']!r}"
    return resp["Entries"][0]["EventId"]


def _item(ctx, table, item_id):
    return ctx.client("dynamodb").get_item(
        TableName=table, Key={"id": {"S": item_id}}, ConsistentRead=True
    ).get("Item")


def _scan_ids(ctx, table):
    ddb = ctx.client("dynamodb")
    ids = []
    for page in ddb.get_paginator("scan").paginate(TableName=table, ConsistentRead=True):
        ids.extend(i["id"]["S"] for i in page["Items"])
    return sorted(ids)


def _metric_sum(ctx, metric, bus, rule, since):
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": "EventBusName", "Value": bus}, {"Name": "RuleName", "Value": rule}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(p["Sum"] for p in resp["Datapoints"])


# ===== the check =====
# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:rejection",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c2",
    "timing:real-time",
)
def run(ctx) -> None:
    """An EventBridge AppSync target whose RoleArn trusts events.amazonaws.com but lacks
    appsync:GraphQL is refused at delivery: the resolver never writes, the transformed input is
    dead-lettered with NO_PERMISSIONS, and AWS/Events FailedInvocations counts it for that rule.
    """
    events = ctx.client("events")
    ident = ctx.client("sts").get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    sfx = uuid.uuid4().hex[:10]

    # Roles first, so their trust has propagated by the time the first event is delivered.
    good_role_name = f"sim2real-xsvc-as2-good-{sfx}"
    bad_role_name = f"sim2real-xsvc-as2-bad-{sfx}"
    good_role = _create_role(ctx, good_role_name, "events.amazonaws.com")
    bad_role = _create_role(ctx, bad_role_name, "events.amazonaws.com")
    ds_role_name = f"sim2real-xsvc-as2-ds-{sfx}"
    ds_role = _create_role(ctx, ds_role_name, "appsync.amazonaws.com")

    table = f"sim2real-xsvc-as2-{sfx}"
    table_arn = _create_table(ctx, table)
    _put_policy(ctx, ds_role_name, [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}])
    time.sleep(8)  # IAM propagation exposes no pollable condition; the bounded retries below decide
    api_id, uri = _create_api(ctx, f"sim2real-xsvc-as2-{sfx}", ds_role, table)
    api_arn = f"arn:{partition}:appsync:{ctx.region}:{account}:apis/{api_id}"
    field_arn = f"{api_arn}/types/Mutation/fields/putItem"
    _put_policy(ctx, good_role_name, [{"Effect": "Allow", "Action": "appsync:GraphQL", "Resource": field_arn}])
    # The ONE broken thing: trusted by events.amazonaws.com, but its only grant on the API is a
    # near-miss control-plane action — no appsync:GraphQL.
    _put_policy(ctx, bad_role_name, [{"Effect": "Allow", "Action": "appsync:GetGraphqlApi", "Resource": api_arn}])
    warm_id = f"warm-{sfx}"
    _warm_resolver(ctx, uri, warm_id)

    bus = f"sim2real-xsvc-as2-{sfx}"
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))
    dlq_url, dlq_arn = _create_dlq(
        ctx, f"sim2real-xsvc-as2-dlq-{sfx}", f"arn:{partition}:events:{ctx.region}:{account}:rule/{bus}/*"
    )
    target_arn = _target_arn(ctx, uri)
    pattern = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}

    def _target(role, prefix):
        return {
            "Id": "appsync",
            "Arn": target_arn,
            "RoleArn": role,
            "AppSyncParameters": {"GraphQLOperation": _MUTATION},
            "InputTransformer": {
                "InputPathsMap": {"id": "$.detail.id", "kind": "$.detail.kind"},
                "InputTemplate": '{"id": "%s<id>", "kind": <kind>}' % prefix,
            },
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        }

    good_rule = f"sim2real-xsvc-as2-good-{sfx}"
    bad_rule = f"sim2real-xsvc-as2-bad-{sfx}"
    good_rule_arn = _make_rule(ctx, bus, good_rule, pattern, _target(good_role, "ok-"))
    bad_rule_arn = _make_rule(ctx, bus, bad_rule, pattern, _target(bad_role, "denied-"))

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    rounds, good_ran, good_dead = [], [], 0
    final_dead = None
    for _ in range(5):
        item_id = uuid.uuid4().hex[:12]
        _fire(ctx, bus, item_id, "widget")
        rounds.append(item_id)
        dead, strays = {}, []

        def _probe():
            for m in _drain(ctx, dlq_url, seconds=3):
                body = json.loads(m["Body"])
                rule = _attr(m, "RULE_ARN")
                expect = {good_rule_arn: "ok-", bad_rule_arn: "denied-"}.get(rule)
                if expect and body.get("id") == expect + item_id and rule not in dead:
                    dead[rule] = m
                else:
                    strays.append(m)
            resolved = set(dead)
            if good_rule_arn not in dead and _item(ctx, table, "ok-" + item_id):
                resolved.add(good_rule_arn)
            if bad_rule_arn not in dead and _item(ctx, table, "denied-" + item_id):
                resolved.add(bad_rule_arn)
            return resolved

        _poll_until(
            _probe,
            lambda r: r == {good_rule_arn, bad_rule_arn},
            timeout_s=120,
            interval_s=1,
            description=f"both rules resolved event {item_id!r} (item written or dead-lettered)",
        )
        assert strays == [], (
            f"the DLQ held copies this round did not produce: "
            f"{[(_attr(m, 'RULE_ARN'), _attr(m, 'ERROR_CODE'), m['Body']) for m in strays]!r}"
        )
        assert bad_rule_arn in dead, (
            f"the role without appsync:GraphQL WROTE {_item(ctx, table, 'denied-' + item_id)!r} through "
            f"the mutation; EventBridge must be refused by the AppSync endpoint"
        )
        if good_rule_arn in dead:
            code = _attr(dead[good_rule_arn], "ERROR_CODE")
            # Bounded retry: a just-created role whose trust (FAILED_TO_ASSUME_ROLE) or inline
            # grant (NO_PERMISSIONS) has not propagated yet re-fires; anything else fails now.
            if code in _PROPAGATION_CODES:
                good_dead += 1
                continue
            raise AssertionError(
                f"the healthy rule was dead-lettered with ERROR_CODE={code!r}: "
                f"{_attr(dead[good_rule_arn], 'ERROR_MESSAGE')!r}"
            )
        good_ran.append(item_id)
        code = _attr(dead[bad_rule_arn], "ERROR_CODE")
        if code == "NO_PERMISSIONS":
            final_dead = dead[bad_rule_arn]
            break
        assert code == "FAILED_TO_ASSUME_ROLE", (
            f"DLQ ERROR_CODE={code!r} for the denied rule, expected 'NO_PERMISSIONS'. "
            f"ERROR_MESSAGE={_attr(dead[bad_rule_arn], 'ERROR_MESSAGE')!r}"
        )
    assert final_dead is not None, (
        f"{len(rounds)} rounds never showed the healthy rule writing beside the denied rule "
        f"dead-lettered with NO_PERMISSIONS (healthy rule dead-lettered {good_dead} time(s))"
    )
    final_id = rounds[-1]

    message = _attr(final_dead, "ERROR_MESSAGE") or ""
    assert '"401"' in message and "Unauthorized" in message, (
        f"ERROR_MESSAGE does not carry the AppSync endpoint's 401 Unauthorized refusal: {message!r}"
    )
    assert _attr(final_dead, "TARGET_ARN") == target_arn, (
        f"DLQ TARGET_ARN={_attr(final_dead, 'TARGET_ARN')!r}, expected {target_arn!r}"
    )
    body = json.loads(final_dead["Body"])
    assert body == {"id": "denied-" + final_id, "kind": "widget"}, (
        f"the dead-lettered body is not the InputTransformer's output for this event: {body!r}"
    )
    assert _item(ctx, table, "ok-" + final_id) == {"id": {"S": "ok-" + final_id}, "kind": {"S": "widget"}}, (
        f"the healthy sibling's item for the same event is {_item(ctx, table, 'ok-' + final_id)!r}"
    )

    # The service's own per-rule record. Every round dead-lettered the denied rule exactly once
    # (MaximumRetryAttempts=0); the sibling failed only in the rounds we saw it dead-lettered.
    def _metrics():
        return (
            _metric_sum(ctx, "FailedInvocations", bus, bad_rule, window_start),
            _metric_sum(ctx, "Invocations", bus, good_rule, window_start),
            _metric_sum(ctx, "FailedInvocations", bus, good_rule, window_start),
        )

    bad_failed, good_inv, good_failed = _poll_until(
        _metrics,
        lambda m: m[0] >= len(rounds) and m[1] >= len(good_ran) and m[2] >= good_dead,
        timeout_s=300,
        interval_s=10,
        description=(
            f"AWS/Events FailedInvocations[{bad_rule}] >= {len(rounds)} and "
            f"Invocations[{good_rule}] >= {len(good_ran)}"
        ),
    )
    assert bad_failed == len(rounds), (
        f"FailedInvocations for the denied rule = {bad_failed}, expected exactly {len(rounds)} "
        f"(one per event, MaximumRetryAttempts=0)"
    )
    assert good_failed == good_dead, (
        f"FailedInvocations for the healthy sibling = {good_failed}, expected {good_dead} (the rounds "
        f"it was itself dead-lettered) — the denied rule's failures must not be attributed to a sibling"
    )

    ids = _scan_ids(ctx, table)
    expected = sorted([warm_id] + ["ok-" + i for i in good_ran])
    assert ids == expected, (
        f"the table holds {ids!r}, expected only the warm-up and the healthy rule's items {expected!r} "
        f"— no 'denied-' item may exist"
    )
    extra = _drain(ctx, dlq_url, seconds=5)
    assert extra == [], (
        f"the DLQ received {len(extra)} further message(s): "
        f"{[(_attr(m, 'RULE_ARN'), _attr(m, 'ERROR_CODE')) for m in extra]!r}"
    )

    # REPAIR the one broken thing and demand the identical wiring now write through the mutation.
    _put_policy(ctx, bad_role_name, [{"Effect": "Allow", "Action": "appsync:GraphQL", "Resource": field_arn}])
    repaired = []

    def _refire_and_look():
        repaired.append(uuid.uuid4().hex[:12])
        _fire(ctx, bus, repaired[-1], "gadget")
        time.sleep(10)
        return [i for i in _scan_ids(ctx, table) if i.startswith("denied-")]

    landed = _poll_until(
        _refire_and_look,
        lambda ids_: len(ids_) >= 1,
        timeout_s=240,
        interval_s=0,
        description=f"after granting appsync:GraphQL, {bad_rule} wrote a 'denied-' item",
    )
    assert set(landed) <= {"denied-" + r for r in repaired}, (
        f"the repaired rule wrote {landed!r}; only post-repair events {repaired!r} may land — the "
        f"dead-lettered events must not be replayed"
    )
    first = landed[0]
    assert _item(ctx, table, first) == {"id": {"S": first}, "kind": {"S": "gadget"}}, (
        f"the repaired rule's item is {_item(ctx, table, first)!r}, expected kind 'gadget'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
