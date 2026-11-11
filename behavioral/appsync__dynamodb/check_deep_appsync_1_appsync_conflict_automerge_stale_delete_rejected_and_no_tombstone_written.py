"""deep-appsync-1-appsync-conflict-automerge-stale-delete-rejected-and-no-tombstone-written."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-1-appsync-conflict-automerge-stale-delete-rejected-and-no-tombstone-written"
GROUP = 'concurrency'
SERVICES = ['appsync', 'dynamodb']

SDL = """schema { query: Query mutation: Mutation }
type Post {
    id: ID!
    title: String
    _version: Int
    _deleted: Boolean
    _lastChangedAt: AWSTimestamp
}
type Query {
    getPost(id: ID!): Post
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

# `expressionNames` is load-bearing on a versioned resolver.
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

# On a VERSIONED data source a DeleteItem is a SOFT delete: it writes `_deleted: true` and a
# `_ttl` tombstone instead of removing the row (measured).
VTL_DELETE = """{
    "version": "2018-05-29",
    "operation": "DeleteItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "_version": $util.toJson($ctx.args.expectedVersion)
}"""

VTL_RESPONSE = """#if( $ctx.error )
    $util.error($ctx.error.message, $ctx.error.type, $ctx.result)
#end
$util.toJson($ctx.result)"""

SYNC_CONFIG = {"conflictHandler": "AUTOMERGE", "conflictDetection": "VERSION"}

FIELDS = "{ id title _version _deleted _lastChangedAt }"


# ===== shared helpers (self-contained) =====


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK[:250]}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
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
    """Create an IAM role trusted by ``trust_service`` and register its teardown.

    IAM exposes no condition reporting that a role has become usable; the bounded retry at
    FIRST USE (the seed write in ``run``) is what makes the check correct.
    """
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

    Returns (svc, api_id, graphql_uri, ds_name, base_table, api_key).
    """
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
    """AppSync's use of its freshly created service role flaps for a while after creation.

    MEASURED on real AWS, two shapes: `Unauthorized` / "Unable to assume role" (also seen on a
    THIRD call, well after a first success), and `DynamoDB:DynamoDbException` / "The security
    token included in the request is invalid" on the very first call. Neither reached the
    table, so a retry cannot double-apply a write.
    """
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


# ===== end shared helpers =====


def _item(ddb, table, item_id):
    return ddb.get_item(
        TableName=table, Key={"id": {"S": item_id}}, ConsistentRead=True
    ).get("Item")


def _one_error(body):
    errors = (body or {}).get("errors") or []
    assert len(errors) == 1, f"expected exactly one GraphQL error, got {body!r}"
    return errors[0]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """AUTOMERGE merges a stale UPDATE but REFUSES a stale DELETE, and writes no tombstone.

    The refusal carries the live server item; DynamoDB's `_version`, `_deleted` and `_ttl`
    stay unmoved, with only `expectedVersion` differing from the positive control that follows.
    """
    ddb = ctx.client("dynamodb")
    svc, api_id, uri, ds_name, base_table, api_key = _versioned_dynamodb_api(ctx, SDL)
    for field, template in (("createPost", VTL_CREATE), ("setTitle", VTL_SET_TITLE),
                            ("deletePost", VTL_DELETE)):
        svc.create_resolver(
            apiId=api_id, typeName="Mutation", fieldName=field,
            kind="UNIT", dataSourceName=ds_name,
            requestMappingTemplate=template, responseMappingTemplate=VTL_RESPONSE,
            syncConfig=SYNC_CONFIG,
        )
        ctx.on_cleanup(
            lambda _f=field: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName=_f)
        )
    gql = _gql_client(ctx, uri, api_key)

    post_id = ctx.unique_name("post-")
    title_seed = ctx.unique_name("seed-")
    title_v2 = ctx.unique_name("v2-")
    create = ("mutation C($id: ID!, $title: String!) "
              "{ createPost(id: $id, title: $title) %s }" % FIELDS)
    delete = ("mutation D($id: ID!, $v: Int!) "
              "{ deletePost(id: $id, expectedVersion: $v) %s }" % FIELDS)
    set_title = ("mutation S($id: ID!, $value: String!, $v: Int!) "
                 "{ setTitle(id: $id, value: $value, expectedVersion: $v) %s }" % FIELDS)

    seeded = _ok(_poll_until(
        lambda: gql(create, {"id": post_id, "title": title_seed}),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the versioned DynamoDB resolver to become invocable (IAM propagation)",
    ), "createPost")
    assert seeded["_version"] == 1, f"a versioned create must stamp _version 1: {seeded!r}"
    moved = _ok(gql(set_title, {"id": post_id, "value": title_v2, "v": 1}), "setTitle")
    assert moved["_version"] == 2, f"a current-version update must reach v2: {moved!r}"
    before = _item(ddb, base_table, post_id)
    assert before is not None and before["_version"]["N"] == "2", (
        f"the v2 item is not in DynamoDB: {before!r}"
    )

    # ---- break exactly one thing: delete carrying the STALE version 1 ----
    status, refused = gql(delete, {"id": post_id, "v": 1})
    assert status == 200, (
        f"a conflict is reported inside a GraphQL 200, not at the transport; got {status!r}: "
        f"{refused!r}"
    )
    error = _one_error(refused)
    assert error.get("errorType") == "ConflictUnhandled", (
        f"AUTOMERGE must refuse a stale delete; got errorType {error.get('errorType')!r} in "
        f"{refused!r}"
    )
    assert error.get("path") == ["deletePost"], f"the refusal must name its field: {error!r}"
    assert (refused.get("data") or {}).get("deletePost") is None, (
        f"the refused delete returned data as well as a conflict: {refused!r}"
    )
    server_item = error.get("data")
    assert isinstance(server_item, dict), (
        f"the refusal must carry the CURRENT server item, got no `data`: {error!r}"
    )
    assert server_item.get("_version") == 2 and server_item.get("title") == title_v2, (
        f"the refusal's item is not the live v2 server state: {server_item!r}"
    )
    assert server_item.get("_deleted") is None, (
        f"the refusal reported the item as deleted: {server_item!r}"
    )

    # ---- the effect is absent in DynamoDB: no tombstone, no TTL, version unmoved ----
    after = _item(ddb, base_table, post_id)
    assert after is not None, f"the refused delete removed the row: {post_id!r}"
    assert "_deleted" not in after, f"the refused delete wrote a tombstone: {after!r}"
    assert "_ttl" not in after, f"the refused delete scheduled the row for expiry: {after!r}"
    assert after["_version"]["N"] == "2", f"the refused delete moved _version: {after!r}"
    assert after["_lastChangedAt"] == before["_lastChangedAt"], (
        f"the refused delete touched _lastChangedAt: {before!r} -> {after!r}"
    )
    assert after["title"]["S"] == title_v2, f"the refused delete changed the item: {after!r}"

    # ---- positive control: the same delete at the CURRENT version tombstones the item ----
    deleted = _ok(gql(delete, {"id": post_id, "v": server_item["_version"]}), "deletePost")
    assert deleted["_deleted"] is True, (
        f"a current-version delete must report _deleted true: {deleted!r}"
    )
    assert deleted["_version"] == 3, f"the delete must advance _version to 3: {deleted!r}"
    tomb = _item(ddb, base_table, post_id)
    assert tomb is not None, (
        f"a versioned delete is a SOFT delete; the row must remain as a tombstone: {post_id!r}"
    )
    assert tomb.get("_deleted") == {"BOOL": True}, f"no tombstone in DynamoDB: {tomb!r}"
    assert "N" in tomb.get("_ttl", {}), f"the tombstone carries no _ttl: {tomb!r}"
    assert tomb["_version"]["N"] == "3", f"the tombstone _version is not 3: {tomb!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
