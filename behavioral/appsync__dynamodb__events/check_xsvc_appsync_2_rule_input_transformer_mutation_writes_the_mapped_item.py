"""xsvc-appsync-2-rule-input-transformer-mutation-writes-the-mapped-item."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from behavioral_harness import tags

CHECK = "xsvc-appsync-2-rule-input-transformer-mutation-writes-the-mapped-item"
GROUP = "event-propagation"
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
_GET_REQUEST = (
    '{"version": "2018-05-29", "operation": "GetItem", "consistentRead": true, '
    '"key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)}}'
)
_PASSTHROUGH_RESPONSE = "$util.toJson($ctx.result)"

_MUTATION = "mutation PutItem($id: ID!, $kind: String!) { putItem(id: $id, kind: $kind) { id kind } }"
_QUERY = "query GetItem($id: ID!) { getItem(id: $id) { id kind } }"

# DLQ codes a brand-new role produces while IAM propagates — the only reason to re-fire.
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
    """AWS_IAM GraphQL API: Mutation.putItem is a VTL PutItem into `table`, Query.getItem a
    consistent GetItem from it. Returns (api_id, graphql_uri)."""
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
    for type_name, field, request in (("Mutation", "putItem", _PUT_REQUEST), ("Query", "getItem", _GET_REQUEST)):
        ap.create_resolver(
            apiId=api_id,
            typeName=type_name,
            fieldName=field,
            dataSourceName="items",
            requestMappingTemplate=request,
            responseMappingTemplate=_PASSTHROUGH_RESPONSE,
        )
        ctx.on_cleanup(
            lambda t=type_name, f=field: ctx.client("appsync").delete_resolver(
                apiId=api_id, typeName=t, fieldName=f
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


# ===== the check =====
@tags(
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
    "axis:happy-path",
    "cap:c2",
)
def run(ctx) -> None:
    """A rule targeting an AppSync GraphQL mutation writes exactly the item its InputTransformer
    maps ($.detail.id, $.detail.kind) per event, read back by GetItem and a signed GraphQL query.
    """
    events = ctx.client("events")
    ident = ctx.client("sts").get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    sfx = uuid.uuid4().hex[:10]

    role_name = f"sim2real-xsvc-as2-ev-{sfx}"
    role_arn = _create_role(ctx, role_name, "events.amazonaws.com")
    ds_role_name = f"sim2real-xsvc-as2-ds-{sfx}"
    ds_role = _create_role(ctx, ds_role_name, "appsync.amazonaws.com")
    table = f"sim2real-xsvc-as2-{sfx}"
    table_arn = _create_table(ctx, table)
    _put_policy(
        ctx, ds_role_name,
        [{"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem"], "Resource": table_arn}],
    )
    api_id, uri = _create_api(ctx, f"sim2real-xsvc-as2-{sfx}", ds_role, table)
    field_arn = f"arn:{partition}:appsync:{ctx.region}:{account}:apis/{api_id}/types/Mutation/fields/putItem"
    _put_policy(ctx, role_name, [{"Effect": "Allow", "Action": "appsync:GraphQL", "Resource": field_arn}])
    warm_id = f"warm-{sfx}"
    _warm_resolver(ctx, uri, warm_id)

    bus = f"sim2real-xsvc-as2-{sfx}"
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))
    dlq_url, dlq_arn = _create_dlq(
        ctx, f"sim2real-xsvc-as2-dlq-{sfx}", f"arn:{partition}:events:{ctx.region}:{account}:rule/{bus}/*"
    )
    target_arn = _target_arn(ctx, uri)
    rule = f"sim2real-xsvc-as2-{sfx}"
    rule_arn = _make_rule(
        ctx, bus, rule,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]},
        {
            "Id": "appsync",
            "Arn": target_arn,
            "RoleArn": role_arn,
            "AppSyncParameters": {"GraphQLOperation": _MUTATION},
            "InputTransformer": {
                "InputPathsMap": {"id": "$.detail.id", "kind": "$.detail.kind"},
                "InputTemplate": '{"id": <id>, "kind": <kind>}',
            },
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        },
    )
    listed = events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]
    assert [t["AppSyncParameters"]["GraphQLOperation"] for t in listed] == [_MUTATION], (
        f"ListTargetsByRule does not echo the GraphQL operation: {listed!r}"
    )

    landed = {}  # id -> kind, for the round in which BOTH events were delivered
    every_write = {}  # id -> kind, for every event the resolver wrote in any round
    rounds = 0
    while not landed and rounds < 5:
        rounds += 1
        batch = {f"{uuid.uuid4().hex[:12]}": "widget", f"{uuid.uuid4().hex[:12]}": "gadget"}
        resp = events.put_events(
            Entries=[
                {
                    "EventBusName": bus,
                    "Source": _SOURCE,
                    "DetailType": _DETAIL_TYPE,
                    # Fields the transformer does NOT map must not reach the table.
                    "Detail": json.dumps({"id": i, "kind": k, "extra": "dropped", "nested": {"n": 1}}),
                }
                for i, k in batch.items()
            ]
        )
        assert resp["FailedEntryCount"] == 0, f"PutEvents refused an entry: {resp['Entries']!r}"
        written, dead, strays = {}, {}, []

        def _probe():
            for m in _drain(ctx, dlq_url, seconds=3):
                body = json.loads(m["Body"])
                if _attr(m, "RULE_ARN") == rule_arn and body.get("id") in batch:
                    dead[body["id"]] = m
                else:
                    strays.append(m)
            for i in batch:
                if i not in dead and i not in written:
                    got = _item(ctx, table, i)
                    if got:
                        written[i] = got
            return set(written) | set(dead)

        _poll_until(
            _probe,
            lambda r: r == set(batch),
            timeout_s=120,
            interval_s=1,
            description=f"both events {sorted(batch)!r} written by the resolver or dead-lettered",
        )
        assert strays == [], f"the DLQ held messages no event of this round produced: {strays!r}"
        for i, got in written.items():
            assert got == {"id": {"S": i}, "kind": {"S": batch[i]}}, (
                f"the item for event {i!r} is {got!r}; expected exactly id={i!r}, kind={batch[i]!r} — "
                f"the InputTransformer maps only $.detail.id and $.detail.kind"
            )
            every_write[i] = batch[i]
        for i, m in dead.items():
            code = _attr(m, "ERROR_CODE")
            if code not in _PROPAGATION_CODES:
                raise AssertionError(
                    f"event {i!r} was dead-lettered with ERROR_CODE={code!r}: {_attr(m, 'ERROR_MESSAGE')!r}"
                )
        if dead:
            continue  # the new role had not propagated: re-fire a fresh pair
        landed = dict(batch)
    assert landed, f"{rounds} rounds never delivered a pair of events through the mutation"

    # The same items, read back through the API's OWN endpoint with a signed GraphQL query.
    for i, k in every_write.items():
        status, body = _signed_graphql(ctx, uri, _QUERY, {"id": i})
        assert status == 200 and not body.get("errors"), f"getItem({i!r}) returned {status!r} {body!r}"
        assert body["data"]["getItem"] == {"id": i, "kind": k}, (
            f"getItem({i!r}) through the GraphQL endpoint returned {body['data']['getItem']!r}"
        )

    # Exactly one item per delivered event (plus the warm-up), and nothing dead-lettered after.
    ids = _scan_ids(ctx, table)
    assert ids == sorted([warm_id, *every_write]), (
        f"the table holds {ids!r}, expected the warm-up and the delivered events {sorted(every_write)!r}"
    )
    extra = _drain(ctx, dlq_url, seconds=5)
    assert extra == [], f"the DLQ received {len(extra)} message(s) after delivery: {extra!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
