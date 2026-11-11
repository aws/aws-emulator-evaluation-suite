"""deep-appsync-1-appsync-conflict-sync-delta-returns-only-changes-after-lastsync-with-tombstone."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-1-appsync-conflict-sync-delta-returns-only-changes-after-lastsync-with-tombstone"
GROUP = 'consistency'
SERVICES = ['appsync', 'dynamodb']

SDL = """schema { query: Query mutation: Mutation }
type Post {
    id: ID!
    title: String
    _version: Int
    _deleted: Boolean
    _lastChangedAt: AWSTimestamp
}
type PostConnection {
    items: [Post]
    nextToken: String
    startedAt: AWSTimestamp
}
type Query {
    syncPosts(limit: Int, nextToken: String, lastSync: AWSTimestamp): PostConnection
}
type Mutation {
    createPost(id: ID!, title: String!): Post
    setTitle(id: ID!, value: String!, expectedVersion: Int!): Post
    deletePost(id: ID!, expectedVersion: Int!): Post
}
"""

VTL_CREATE = """{
    "version": "2018-05-29",
    "operation": "PutItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "attributeValues": {"title": $util.dynamodb.toDynamoDBJson($ctx.args.title)},
    "_version": 1
}"""

VTL_SET_TITLE = """{
    "version": "2018-05-29",
    "operation": "UpdateItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "update": {
        "expression": "SET #a = :v",
        "expressionNames": {"#a": "title"},
        "expressionValues": {":v": $util.dynamodb.toDynamoDBJson($ctx.args.value)}
    },
    "_version": $util.toJson($ctx.args.expectedVersion)
}"""

VTL_DELETE = """{
    "version": "2018-05-29",
    "operation": "DeleteItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "_version": $util.toJson($ctx.args.expectedVersion)
}"""

# The `Sync` operation is only legal on a VERSIONED data source. With `lastSync` inside the
# deltaSyncTableTTL window AppSync answers from the DELTA table; without it, from the base table.
VTL_SYNC = """{
    "version": "2018-05-29",
    "operation": "Sync",
    "limit": $util.defaultIfNull($ctx.args.limit, 100),
    "nextToken": $util.toJson($util.defaultIfNull($ctx.args.nextToken, null)),
    "lastSync": $util.toJson($util.defaultIfNull($ctx.args.lastSync, null))
}"""

VTL_RESPONSE = """#if( $ctx.error )
    $util.error($ctx.error.message, $ctx.error.type, $ctx.result)
#end
$util.toJson($ctx.result)"""

SYNC_CONFIG = {"conflictHandler": "AUTOMERGE", "conflictDetection": "VERSION"}

FIELDS = "{ id title _version _deleted _lastChangedAt }"


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK[:250]}, {"Key": "sim2real:managed", "Value": "true"}]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition",
                budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait for {description} ended (last={last!r}); not graded"
        )
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(url, headers, payload, timeout_s=30):
    """POST JSON and return (status, parsed_body); a 4xx/5xx is returned, not raised."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, trust_service, inline_policy):
    """Create an IAM role trusted by ``trust_service`` and register its teardown; readiness is
    handled by the bounded retry at first use."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-role-")
    resp = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                        PolicyDocument=json.dumps(inline_policy))
    return resp["Role"]["Arn"]


def _create_table(ctx, prefix, keys):
    """An on-demand DynamoDB table with STRING keys ``[(name, HASH|RANGE), ...]``."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name(prefix)
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": k, "KeyType": t} for k, t in keys],
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k, _ in keys],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0, interval_s=2.0,
        description=f"DynamoDB table {name} reaching ACTIVE",
    )
    return name, resp["TableDescription"]["TableArn"]


def _graphql_api(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + an ACTIVE schema; return (api_id, graphql_uri)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK[:256], "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=120.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: {status!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    return api_id, uri


def _versioned_dynamodb_api(ctx, sdl):
    """Base table + delta table + role + API + VERSIONED data source with deltaSyncConfig.
    Returns (svc, api_id, graphql_uri, ds_name, base_table, api_key)."""
    svc = ctx.client("appsync")
    base_table, base_arn = _create_table(ctx, "sim2real-behav-appsync-", [("id", "HASH")])
    delta_table, delta_arn = _create_table(
        ctx, "sim2real-behav-appsync-delta-", [("ds_pk", "HASH"), ("ds_sk", "RANGE")]
    )
    role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem",
                                  "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan",
                                  "dynamodb:ConditionCheckItem", "dynamodb:BatchWriteItem"],
                       "Resource": [base_arn, base_arn + "/*", delta_arn, delta_arn + "/*"]}],
    })
    api_id, uri = _graphql_api(ctx, svc, sdl)
    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(
        apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB", serviceRoleArn=role_arn,
        dynamodbConfig={
            "tableName": base_table,
            "awsRegion": ctx.region,
            "versioned": True,
            "deltaSyncConfig": {
                "baseTableTTL": 43200,
                "deltaSyncTableName": delta_table,
                "deltaSyncTableTTL": 60,
            },
        },
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync conflict key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))
    return svc, api_id, uri, ds_name, base_table, api_key


def _is_transient_credential_error(res):
    """True for the errors AppSync returns while a new service role propagates ("Unable to assume
    role", "security token ... invalid"); neither reaches the table, so a retry is safe."""
    status, body = res
    errors = (body or {}).get("errors") or []
    if status != 200 or len(errors) != 1:
        return False
    etype = errors[0].get("errorType") or ""
    msg = errors[0].get("message") or ""
    return (
        (etype == "Unauthorized" and "Unable to assume role" in msg)
        or (etype.startswith("DynamoDB:") and "security token" in msg)
    )


def _gql_client(ctx, uri, api_key):
    # The published URI, at the target that serves it: an emulator serves an AWS host itself.
    target, route = ctx.endpoint_route(uri)

    def gql(query, variables, *, timeout_s=60.0):
        return _poll_until(
            lambda: _post_json(target, {"x-api-key": api_key, **route},
                               {"query": query, "variables": variables}),
            lambda res: not _is_transient_credential_error(res),
            timeout_s=timeout_s, interval_s=3.0,
            description="AppSync's use of its own DynamoDB service role to stop flapping",
        )
    return gql


def _ok(res, field):
    """The `data.<field>` object of a GraphQL 200 that carried no errors."""
    status, body = res
    assert status == 200 and not (body or {}).get("errors"), (
        f"{field} was expected to succeed; got HTTP {status!r}: {body!r}"
    )
    out = (body.get("data") or {}).get(field)
    assert isinstance(out, dict), f"{field} returned no object: {body!r}"
    return out




def _item(ddb, table, item_id):
    return ddb.get_item(
        TableName=table, Key={"id": {"S": item_id}}, ConsistentRead=True
    ).get("Item")


@tags("concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """Once visible, a delta Sync from a `lastSync` cursor returns exactly the update, delete
    (`_deleted: true`) and create made since, the deleted row stays tombstoned in the base
    table, and the next cursor's delta is empty.
    """
    ddb = ctx.client("dynamodb")
    svc, api_id, uri, ds_name, base_table, api_key = _versioned_dynamodb_api(ctx, SDL)
    for type_name, field, template in (
        ("Mutation", "createPost", VTL_CREATE),
        ("Mutation", "setTitle", VTL_SET_TITLE),
        ("Mutation", "deletePost", VTL_DELETE),
        ("Query", "syncPosts", VTL_SYNC),
    ):
        svc.create_resolver(
            apiId=api_id, typeName=type_name, fieldName=field,
            kind="UNIT", dataSourceName=ds_name,
            requestMappingTemplate=template, responseMappingTemplate=VTL_RESPONSE,
            syncConfig=SYNC_CONFIG,
        )
        ctx.on_cleanup(
            lambda _t=type_name, _f=field: svc.delete_resolver(
                apiId=api_id, typeName=_t, fieldName=_f
            )
        )
    gql = _gql_client(ctx, uri, api_key)

    create = ("mutation C($id: ID!, $title: String!) "
              "{ createPost(id: $id, title: $title) %s }" % FIELDS)
    set_title = ("mutation S($id: ID!, $value: String!, $v: Int!) "
                 "{ setTitle(id: $id, value: $value, expectedVersion: $v) %s }" % FIELDS)
    delete = ("mutation D($id: ID!, $v: Int!) "
              "{ deletePost(id: $id, expectedVersion: $v) %s }" % FIELDS)
    sync = ("query Q($lastSync: AWSTimestamp) "
            "{ syncPosts(limit: 100, lastSync: $lastSync) { items %s nextToken startedAt } }"
            % FIELDS)

    def do_sync(last_sync):
        out = _ok(gql(sync, {"lastSync": last_sync}), "syncPosts")
        assert out.get("nextToken") is None, (
            f"a handful of items must fit in one page of 100: {out!r}"
        )
        assert isinstance(out.get("startedAt"), int), f"Sync returned no startedAt cursor: {out!r}"
        return out

    kept = ctx.unique_name("kept-")
    updated = ctx.unique_name("updated-")
    deleted = ctx.unique_name("deleted-")
    added = ctx.unique_name("added-")
    new_title = ctx.unique_name("retitled-")

    _ok(_poll_until(
        lambda: gql(create, {"id": kept, "title": "seed"}),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the versioned DynamoDB resolver to become invocable (IAM propagation)",
    ), "createPost")
    for item_id in (updated, deleted):
        _ok(gql(create, {"id": item_id, "title": "seed"}), "createPost")

    # A full (base-table) Sync returns every live item and mints the cursor. Sync reads the
    # tables with eventually consistent Scan/Query, so a just-written item may lag; poll.
    seeded = sorted([kept, updated, deleted])
    baseline = _poll_until(
        lambda: do_sync(None),
        lambda out: sorted(i["id"] for i in out["items"]) == seeded,
        timeout_s=60.0, budget_s=_budget_s(ctx, 60.0), interval_s=2.0,
        description="the full Sync to return the three seeded items",
    )
    base_ids = sorted(i["id"] for i in baseline["items"])
    assert base_ids == sorted([kept, updated, deleted]), (
        f"the baseline full Sync must return exactly the three seeded items: {base_ids!r}"
    )
    cursor = baseline["startedAt"]

    up = _ok(gql(set_title, {"id": updated, "value": new_title, "v": 1}), "setTitle")
    assert up["_version"] == 2, f"the update did not reach v2: {up!r}"
    gone = _ok(gql(delete, {"id": deleted, "v": 1}), "deletePost")
    assert gone["_deleted"] is True, f"the delete did not report _deleted: {gone!r}"
    _ok(gql(create, {"id": added, "title": "late"}), "createPost")

    tomb = _item(ddb, base_table, deleted)
    assert tomb is not None and tomb.get("_deleted") == {"BOOL": True}, (
        f"a versioned delete must leave a `_deleted` tombstone row in the base table: {tomb!r}"
    )

    changed = sorted([updated, deleted, added])
    delta = _poll_until(
        lambda: do_sync(cursor),
        lambda out: sorted({i["id"] for i in out["items"]}) == changed,
        timeout_s=60.0, budget_s=_budget_s(ctx, 60.0), interval_s=2.0,
        description="the delta Sync to return the three changed items",
    )
    by_id = {}
    for rec in delta["items"]:
        assert rec["id"] not in by_id, f"the delta Sync returned {rec['id']!r} twice: {delta!r}"
        by_id[rec["id"]] = rec
    assert sorted(by_id) == sorted([updated, deleted, added]), (
        f"the delta Sync must return exactly the records changed after lastSync={cursor!r} "
        f"(updated, deleted, added) and NOT the untouched {kept!r}; got {sorted(by_id)!r}"
    )
    assert by_id[updated]["title"] == new_title and by_id[updated]["_version"] == 2, (
        f"the delta record for the update is not its new state: {by_id[updated]!r}"
    )
    assert by_id[updated]["_deleted"] is None, (
        f"the updated record must not be flagged deleted: {by_id[updated]!r}"
    )
    assert by_id[deleted]["_deleted"] is True and by_id[deleted]["_version"] == 2, (
        f"the deleted record must come back as a `_deleted: true` tombstone at v2: "
        f"{by_id[deleted]!r}"
    )
    assert by_id[added]["_version"] == 1 and by_id[added]["title"] == "late", (
        f"the record created after the cursor is not its created state: {by_id[added]!r}"
    )
    for rec in by_id.values():
        assert rec["_lastChangedAt"] > cursor, (
            f"the delta Sync returned a record last changed at {rec['_lastChangedAt']!r}, "
            f"not after lastSync={cursor!r}: {rec!r}"
        )
    assert delta["startedAt"] > cursor, (
        f"the delta Sync's cursor did not advance: {cursor!r} -> {delta['startedAt']!r}"
    )

    again = do_sync(delta["startedAt"])
    assert again["items"] == [], (
        f"a Sync from the latest cursor must return no records; got {again['items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
