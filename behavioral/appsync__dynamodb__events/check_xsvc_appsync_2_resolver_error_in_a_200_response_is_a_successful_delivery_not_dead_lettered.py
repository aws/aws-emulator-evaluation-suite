"""xsvc-appsync-2-resolver-error-in-a-200-response-is-a-successful-delivery-not-dead-lettered."""

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

from behavioral_harness import tags

CHECK = "xsvc-appsync-2-resolver-error-in-a-200-response-is-a-successful-delivery-not-dead-lettered"
GROUP = "error-propagation"
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
    putItemBroken(id: ID!, kind: String!): Item
}
"""

_PUT_REQUEST = (
    '{"version": "2018-05-29", "operation": "PutItem", '
    '"key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)}, '
    '"attributeValues": {"kind": $util.dynamodb.toDynamoDBJson($ctx.args.kind)}}'
)
_RAISING_RESPONSE = (
    "#if($ctx.error)\n$util.error($ctx.error.message, $ctx.error.type)\n#end\n$util.toJson($ctx.result)"
)


def _op(field):
    return "mutation PutItem($id: ID!, $kind: String!) { %s(id: $id, kind: $kind) { id kind } }" % field


_MUTATION = _op("putItem")
_BROKEN_MUTATION = _op("putItemBroken")

# DLQ codes a brand-new role produces while IAM propagates — the only reason to re-fire.
_PROPAGATION_CODES = frozenset({"FAILED_TO_ASSUME_ROLE", "NO_PERMISSIONS"})


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


def _create_api(ctx, name, table, fields):
    """AWS_IAM GraphQL API; `fields` maps a Mutation field -> its OWN data-source role ARN, each a
    VTL PutItem into `table` whose response template surfaces a data-source error with
    $util.error. Returns (api_id, graphql_uri)."""
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
    for field, role_arn in fields.items():
        ds = f"ds_{field}"
        ap.create_data_source(
            apiId=api_id,
            name=ds,
            type="AMAZON_DYNAMODB",
            serviceRoleArn=role_arn,
            dynamodbConfig={"tableName": table, "awsRegion": ctx.region},
        )
        ctx.on_cleanup(lambda d=ds: ctx.client("appsync").delete_data_source(apiId=api_id, name=d))
        ap.create_resolver(
            apiId=api_id,
            typeName="Mutation",
            fieldName=field,
            dataSourceName=ds,
            requestMappingTemplate=_PUT_REQUEST,
            responseMappingTemplate=_RAISING_RESPONSE,
        )
        ctx.on_cleanup(
            lambda f=field: ctx.client("appsync").delete_resolver(
                apiId=api_id, typeName="Mutation", fieldName=f
            )
        )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL URI: {api.get('uris')!r}"
    assert not (p := ctx.published_url_mismatch(uri, labels=("appsync-api",), path="/graphql")), p
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
        f"PutTargets on {name} reported FailedEntryCount={put['FailedEntryCount']}: {put['FailedEntries']!r}"
    )
    return arn


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
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "axis:happy-path",
    "cap:c2",
    "timing:real-time",
)
def run(ctx) -> None:
    """An AppSync target whose resolver fails inside a 200 GraphQL response (DynamoDB:DynamoDbException)
    counts as a successful EventBridge invocation: no item, no DLQ message and no FailedInvocations for
    the round that reached the resolver; granting the missing PutItem makes the same wiring write."""
    events = ctx.client("events")
    ident = ctx.client("sts").get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    sfx = uuid.uuid4().hex[:10]

    role_name = f"sim2real-xsvc-as2-ev-{sfx}"
    role_arn = _create_role(ctx, role_name, "events.amazonaws.com")
    ok_ds_name = f"sim2real-xsvc-as2-dsok-{sfx}"
    ok_ds = _create_role(ctx, ok_ds_name, "appsync.amazonaws.com")
    broken_ds_name = f"sim2real-xsvc-as2-dsbad-{sfx}"
    broken_ds = _create_role(ctx, broken_ds_name, "appsync.amazonaws.com")
    table = f"sim2real-xsvc-as2-{sfx}"
    table_arn = _create_table(ctx, table)
    _put_policy(ctx, ok_ds_name, [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}])
    # The ONE broken thing: this data source may read the table but not write it.
    _put_policy(ctx, broken_ds_name, [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": table_arn}])
    time.sleep(8)  # IAM propagation exposes no pollable condition; the bounded retries below decide
    api_id, uri = _create_api(
        ctx, f"sim2real-xsvc-as2-{sfx}", table, {"putItem": ok_ds, "putItemBroken": broken_ds}
    )
    fields = f"arn:{partition}:appsync:{ctx.region}:{account}:apis/{api_id}/types/Mutation/fields/"
    _put_policy(
        ctx, role_name,
        [{"Effect": "Allow", "Action": "appsync:GraphQL",
          "Resource": [fields + "putItem", fields + "putItemBroken"]}],
    )
    warm_id = f"warm-{sfx}"
    _warm_resolver(ctx, uri, warm_id)

    # What the endpoint itself answers for the broken field: HTTP 200 carrying a resolver error.
    direct_id = f"direct-{sfx}"
    status, direct = _signed_graphql(ctx, uri, _BROKEN_MUTATION, {"id": direct_id, "kind": "direct"})
    assert status == 200, f"the broken mutation returned HTTP {status!r} {direct!r}; expected 200"
    errors = direct.get("errors") or []
    assert [e.get("errorType") for e in errors] == ["DynamoDB:DynamoDbException"], (
        f"the broken mutation's errors are {errors!r}; expected one DynamoDB:DynamoDbException"
    )
    assert "dynamodb:PutItem" in errors[0].get("message", ""), (
        f"the resolver error does not name the refused dynamodb:PutItem: {errors[0]!r}"
    )
    assert direct.get("data") == {"putItemBroken": None}, f"data envelope was {direct.get('data')!r}"
    assert _item(ctx, table, direct_id) is None, "the broken data source wrote despite lacking PutItem"

    bus = f"sim2real-xsvc-as2-{sfx}"
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))
    dlq_url, dlq_arn = _create_dlq(
        ctx, f"sim2real-xsvc-as2-dlq-{sfx}", f"arn:{partition}:events:{ctx.region}:{account}:rule/{bus}/*"
    )
    target_arn = _target_arn(ctx, uri)
    pattern = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}

    def _target(operation, prefix):
        return {
            "Id": "appsync",
            "Arn": target_arn,
            "RoleArn": role_arn,
            "AppSyncParameters": {"GraphQLOperation": operation},
            "InputTransformer": {
                "InputPathsMap": {"id": "$.detail.id", "kind": "$.detail.kind"},
                "InputTemplate": '{"id": "%s<id>", "kind": <kind>}' % prefix,
            },
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        }

    good_rule = f"sim2real-xsvc-as2-good-{sfx}"
    broken_rule = f"sim2real-xsvc-as2-brk-{sfx}"
    good_rule_arn = _make_rule(ctx, bus, good_rule, pattern, _target(_MUTATION, "ok-"))
    broken_rule_arn = _make_rule(ctx, bus, broken_rule, pattern, _target(_BROKEN_MUTATION, "broken-"))

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    rounds, propagation_dead = [], {good_rule_arn: 0, broken_rule_arn: 0}
    delivered = None
    for _ in range(5):
        item_id = uuid.uuid4().hex[:12]
        resp = events.put_events(Entries=[{
            "EventBusName": bus, "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"id": item_id, "kind": "widget"}),
        }])
        assert resp["FailedEntryCount"] == 0, f"PutEvents refused the entry: {resp['Entries']!r}"
        rounds.append(item_id)
        dead = []

        def _probe():
            dead.extend(_drain(ctx, dlq_url, seconds=2))
            return _item(ctx, table, "ok-" + item_id)

        got = _poll_until(
            _probe,
            lambda r: r is not None or bool(dead),
            timeout_s=120,
            interval_s=1,
            description=f"the healthy rule wrote ok-{item_id} or something was dead-lettered",
        )
        seen = [(_attr(m, "RULE_ARN"), _attr(m, "ERROR_CODE"), json.loads(m["Body"])) for m in dead]
        # Only the shared target role's propagation may dead-letter anything; such a round does not
        # test the claim for that rule, so it is counted and re-fired.
        for rule, code, _ in seen:
            if rule not in propagation_dead or code not in _PROPAGATION_CODES:
                raise AssertionError(f"event {item_id!r} was dead-lettered: {seen!r}")
            propagation_dead[rule] += 1
        if got is None or seen:
            continue
        delivered = item_id
        break
    assert delivered, f"{len(rounds)} rounds never delivered through the healthy rule"
    assert got == {"id": {"S": "ok-" + delivered}, "kind": {"S": "widget"}}, (
        f"the healthy rule's item is {got!r}"
    )

    # Barrier reached: the SAME event went through the healthy rule. Now the service's own record
    # for the broken rule must show it INVOKED for the delivered round — and not failed for it.
    def _metrics():
        return (
            _metric_sum(ctx, "Invocations", bus, broken_rule, window_start),
            _metric_sum(ctx, "FailedInvocations", bus, broken_rule, window_start),
            _metric_sum(ctx, "Invocations", bus, good_rule, window_start),
        )

    expected_invocations = len(rounds) - propagation_dead[broken_rule_arn]
    brk_inv, brk_failed, good_inv = _poll_until(
        _metrics,
        lambda m: m[0] >= len(rounds) and m[2] >= len(rounds),
        timeout_s=300,
        interval_s=10,
        description=f"AWS/Events Invocations for both rules >= {len(rounds)}",
    )
    assert brk_inv == len(rounds), f"Invocations[{broken_rule}] = {brk_inv}, expected {len(rounds)}"
    assert brk_failed == propagation_dead[broken_rule_arn], (
        f"FailedInvocations[{broken_rule}] = {brk_failed}, expected {propagation_dead[broken_rule_arn]} "
        f"(only role-propagation rounds) — a resolver error inside a 200 GraphQL response is NOT a "
        f"failed invocation ({expected_invocations} round(s) reached the resolver)"
    )
    late = _drain(ctx, dlq_url, seconds=5)
    assert late == [], (
        f"the DLQ received {len(late)} message(s) for the round the resolver rejected: "
        f"{[(_attr(m, 'RULE_ARN'), _attr(m, 'ERROR_CODE'), m['Body']) for m in late]!r}"
    )
    assert _item(ctx, table, "broken-" + delivered) is None, (
        f"the broken data source wrote broken-{delivered}: "
        f"{_item(ctx, table, 'broken-' + delivered)!r}"
    )
    ids = _scan_ids(ctx, table)
    healthy = [r for r in rounds if _item(ctx, table, "ok-" + r)]
    assert ids == sorted([warm_id, *("ok-" + r for r in healthy)]), (
        f"the table holds {ids!r}; only the warm-up and the healthy rule's items may exist"
    )

    # REPAIR the one broken thing: grant the data source PutItem; the identical wiring now writes.
    _put_policy(ctx, broken_ds_name, [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}])
    repaired = []

    def _refire_and_look():
        repaired.append(uuid.uuid4().hex[:12])
        events.put_events(Entries=[{
            "EventBusName": bus, "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"id": repaired[-1], "kind": "gadget"}),
        }])
        time.sleep(10)
        return [i for i in _scan_ids(ctx, table) if i.startswith("broken-")]

    landed = _poll_until(
        _refire_and_look,
        lambda found: len(found) >= 1,
        timeout_s=240,
        interval_s=0,
        description=f"after granting dynamodb:PutItem, {broken_rule} wrote a 'broken-' item",
    )
    assert set(landed) <= {"broken-" + r for r in repaired}, (
        f"the repaired path wrote {landed!r}; only post-repair events {repaired!r} may land"
    )
    assert _item(ctx, table, landed[0]) == {"id": {"S": landed[0]}, "kind": {"S": "gadget"}}, (
        f"the repaired path's item is {_item(ctx, table, landed[0])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
