"""deep-appsync-1-appsync-conflict-automerge-stale-disjoint-writes-both-land-and-same-scalar-keeps-server-value."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-1-appsync-conflict-automerge-stale-disjoint-writes-both-land-and-same-scalar-keeps-server-value"
GROUP = 'concurrency'
SERVICES = ['appsync', 'dynamodb']

SDL = """schema { query: Query mutation: Mutation }
type Post {
    id: ID!
    title: String
    content: String
    summary: String
    tags: [String]
    _version: Int
    _lastChangedAt: AWSTimestamp
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    createPost(id: ID!, title: String!, tags: [String]!): Post
    setTitle(id: ID!, value: String!, expectedVersion: Int!): Post
    setContent(id: ID!, value: String!, expectedVersion: Int!): Post
    setSummary(id: ID!, value: String!, expectedVersion: Int!): Post
    setTags(id: ID!, tags: [String]!, expectedVersion: Int!): Post
}
"""

VTL_CREATE = """{
    "version": "2018-05-29",
    "operation": "PutItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "attributeValues": {
        "title": $util.dynamodb.toDynamoDBJson($ctx.args.title),
        "tags": $util.dynamodb.toDynamoDBJson($ctx.args.tags)
    },
    "_version": 1
}"""


def _vtl_set(attr, arg):
    """A single-attribute versioned UpdateItem.

    The attribute MUST go through `expressionNames`. The same stale update written as a bare
    `SET title = :x` returns `InternalFailure` under AUTOMERGE and never reaches the merge,
    while the `#n` form below merges normally.
    """
    return """{
    "version": "2018-05-29",
    "operation": "UpdateItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "update": {
        "expression": "SET #a = :v",
        "expressionNames": {"#a": "%s"},
        "expressionValues": {":v": $util.dynamodb.toDynamoDBJson($ctx.args.%s)}
    },
    "_version": $util.toJson($ctx.args.expectedVersion)
}""" % (attr, arg)


# Re-raise: a response template that ignores `$ctx.error` swallows a conflict refusal.
VTL_RESPONSE = """#if( $ctx.error )
    $util.error($ctx.error.message, $ctx.error.type, $ctx.result)
#end
$util.toJson($ctx.result)"""

SYNC_CONFIG = {"conflictHandler": "AUTOMERGE", "conflictDetection": "VERSION"}

FIELDS = "{ id title content summary tags _version _lastChangedAt }"


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


@tags("concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """AUTOMERGE merges stale writes per attribute instead of refusing them.

    Disjoint-attribute writers both land and advance `_version`; a stale scalar write keeps the
    SERVER value while still advancing `_version`; a stale list write concatenates server + client.
    """
    ddb = ctx.client("dynamodb")
    svc, api_id, uri, ds_name, base_table, api_key = _versioned_dynamodb_api(ctx, SDL)

    resolvers = [
        ("createPost", VTL_CREATE),
        ("setTitle", _vtl_set("title", "value")),
        ("setContent", _vtl_set("content", "value")),
        ("setSummary", _vtl_set("summary", "value")),
        ("setTags", _vtl_set("tags", "tags")),
    ]
    for field, template in resolvers:
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

    def set_attr(field, item_id, value, version):
        q = ("mutation M($id: ID!, $value: String!, $v: Int!) "
             "{ %s(id: $id, value: $value, expectedVersion: $v) %s }" % (field, FIELDS))
        return gql(q, {"id": item_id, "value": value, "v": version})

    post_id = ctx.unique_name("post-")
    title_seed = ctx.unique_name("seed-")
    title_fresh = ctx.unique_name("fresh-")
    content_x = ctx.unique_name("contentX-")
    summary_y = ctx.unique_name("summaryY-")
    content_z = ctx.unique_name("contentZ-")
    tag_seed = ctx.unique_name("t0-")
    tag_w = ctx.unique_name("tw-")

    # ---- seed at _version 1 (bounded retry at FIRST USE of the new service role) ----
    create = ("mutation C($id: ID!, $title: String!, $tags: [String]!) "
              "{ createPost(id: $id, title: $title, tags: $tags) %s }" % FIELDS)
    seeded = _ok(_poll_until(
        lambda: gql(create, {"id": post_id, "title": title_seed, "tags": [tag_seed]}),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the versioned DynamoDB resolver to become invocable (IAM propagation)",
    ), "createPost")
    assert seeded["_version"] == 1, f"a versioned create must stamp _version 1: {seeded!r}"

    # ---- a current-version write moves the server to v2: every client still at v1 is STALE ----
    fresh = _ok(set_attr("setTitle", post_id, title_fresh, 1), "setTitle")
    assert fresh["_version"] == 2 and fresh["title"] == title_fresh, (
        f"a write carrying the current _version must apply directly and reach v2: {fresh!r}"
    )

    # ---- writer X and writer Y both hold the SAME stale _version 1, different attributes ----
    merged_x = _ok(set_attr("setContent", post_id, content_x, 1), "setContent")
    assert merged_x["content"] == content_x, (
        f"AUTOMERGE dropped writer X's new attribute instead of merging it: {merged_x!r}"
    )
    assert merged_x["title"] == title_fresh, (
        f"the merge for writer X lost the server's v2 title: {merged_x!r}"
    )
    assert merged_x["_version"] == 3, (
        f"a merged stale write must advance _version 2 -> 3, got {merged_x['_version']!r}"
    )
    merged_y = _ok(set_attr("setSummary", post_id, summary_y, 1), "setSummary")
    assert merged_y["summary"] == summary_y and merged_y["content"] == content_x, (
        f"writer Y's merge must carry BOTH its own summary and writer X's content: {merged_y!r}"
    )
    assert merged_y["_version"] == 4, (
        f"two merged stale writes must advance _version by exactly 2 (2 -> 4), got "
        f"{merged_y['_version']!r}"
    )

    # ---- both landed: read the merged item straight out of DynamoDB ----
    stored = _item(ddb, base_table, post_id)
    assert stored is not None, f"the item is missing from the base table: {post_id!r}"
    assert stored.get("content", {}).get("S") == content_x, (
        f"writer X's attribute is not in DynamoDB: {stored!r}"
    )
    assert stored.get("summary", {}).get("S") == summary_y, (
        f"writer Y's attribute is not in DynamoDB: {stored!r}"
    )
    assert stored.get("title", {}).get("S") == title_fresh, (
        f"the v2 title did not survive two merges: {stored!r}"
    )
    assert stored.get("_version", {}).get("N") == "4", (
        f"DynamoDB holds _version {stored.get('_version')!r}; seed + 1 direct + 2 merged = 4"
    )
    changed_at_4 = int(stored["_lastChangedAt"]["N"])

    # ---- same scalar, stale: the SERVER value survives, but the merge is still a write ----
    merged_z = _ok(set_attr("setContent", post_id, content_z, 1), "setContent")
    assert merged_z["content"] == content_x, (
        f"a stale write to a scalar the server already holds must keep the server value "
        f"{content_x!r}; AUTOMERGE returned {merged_z['content']!r} (not last-writer-wins)"
    )
    assert merged_z["_version"] == 5, (
        f"the scalar-conflict merge is still a write and must advance _version to 5: "
        f"{merged_z!r}"
    )
    stored = _item(ddb, base_table, post_id)
    assert stored["content"]["S"] == content_x, (
        f"the losing stale value {content_z!r} reached DynamoDB: {stored!r}"
    )
    assert stored["_version"]["N"] == "5", f"DynamoDB _version is not 5: {stored!r}"
    assert int(stored["_lastChangedAt"]["N"]) > changed_at_4, (
        f"_lastChangedAt did not advance on the scalar-conflict merge: {changed_at_4!r} -> "
        f"{stored['_lastChangedAt']!r}"
    )

    # ---- list, stale: server list + client list are concatenated ----
    tags_q = ("mutation T($id: ID!, $tags: [String]!, $v: Int!) "
              "{ setTags(id: $id, tags: $tags, expectedVersion: $v) %s }" % FIELDS)
    merged_w = _ok(gql(tags_q, {"id": post_id, "tags": [tag_w], "v": 1}), "setTags")
    assert merged_w["tags"] == [tag_seed, tag_w], (
        f"a stale list write must concatenate server {[tag_seed]!r} + client {[tag_w]!r}; "
        f"got {merged_w['tags']!r}"
    )
    assert merged_w["_version"] == 6, f"the list merge must advance _version to 6: {merged_w!r}"
    stored = _item(ddb, base_table, post_id)
    assert [v.get("S") for v in stored.get("tags", {}).get("L", [])] == [tag_seed, tag_w], (
        f"the concatenated list is not what DynamoDB holds: {stored!r}"
    )
    assert stored["_version"]["N"] == "6", f"DynamoDB _version is not 6: {stored!r}"
    assert (
        stored["title"]["S"], stored["content"]["S"], stored["summary"]["S"]
    ) == (title_fresh, content_x, summary_y), (
        f"the list merge disturbed the scalar attributes: {stored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
