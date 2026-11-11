"""appsync-optimistic-concurrency-conflict-returns-server-version-and-data."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-optimistic-concurrency-conflict-returns-server-version-and-data"
GROUP = 'concurrency'
SERVICES = ['appsync', 'dynamodb']

SDL = """schema { query: Query mutation: Mutation }
type Post {
    id: ID!
    title: String
    _version: Int
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    putPost(id: ID!, title: String!, expectedVersion: Int!): Post
    bumpPost(id: ID!, title: String!, expectedVersion: Int!): Post
}
"""

# `_version` is a top-level field of the 2018-05-29 DynamoDB request document and is only
# honoured on a VERSIONED data source; it carries the client's last known version into conflict
# detection. It is not a hand-rolled condition expression.
VTL_PUT = """{
    "version": "2018-05-29",
    "operation": "PutItem",
    "key": {
        "id": $util.dynamodb.toDynamoDBJson($ctx.args.id)
    },
    "attributeValues": {
        "title": $util.dynamodb.toDynamoDBJson($ctx.args.title)
    },
    "_version": $util.toJson($ctx.args.expectedVersion)
}"""

VTL_BUMP = """{
    "version": "2018-05-29",
    "operation": "UpdateItem",
    "key": {
        "id": $util.dynamodb.toDynamoDBJson($ctx.args.id)
    },
    "update": {
        "expression": "SET title = :title",
        "expressionValues": {
            ":title": $util.dynamodb.toDynamoDBJson($ctx.args.title)
        }
    },
    "_version": $util.toJson($ctx.args.expectedVersion)
}"""

# On AWS, a response template that does not inspect `$ctx.error`
# SWALLOWS the refusal entirely -- the plain `$util.toJson($ctx.result)` form returned
# `{"data": {"putPost": null}}` with NO `errors` array, while the row was correctly left
# untouched. Re-raising is therefore load-bearing, and `$ctx.result` on the conflict path is
# where AppSync puts the CURRENT server item.
VTL_RESPONSE = """#if( $ctx.error )
    $util.error($ctx.error.message, $ctx.error.type, $ctx.result)
#end
$util.toJson($ctx.result)"""

SYNC_CONFIG = {"conflictHandler": "OPTIMISTIC_CONCURRENCY", "conflictDetection": "VERSION"}


# ===== helpers =====


_TAGS_KV = None


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


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


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    data = json.dumps(payload).encode()
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
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

    IAM exposes no condition reporting that a trust policy has become effective; the bounded
    retry at FIRST USE of the permission (see the control-write poll in ``run``) is what makes
    the check correct, not a bare wait here.
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


def _create_table(ctx, key="id"):
    """An on-demand DynamoDB table with one STRING hash key. Keys are ALWAYS typed."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
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


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, uris, arn)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType=api_kwargs.pop("authenticationType", "API_KEY"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
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
    uris = api.get("uris") or {}
    assert uris.get("GRAPHQL"), f"the API exposed no GRAPHQL endpoint URI: {uris!r}"
    return api_id, uris, api["arn"]


# ===== end helpers =====

def _create_delta_table(ctx):
    """The Delta table a versioned DynamoDB data source requires: ds_pk (HASH) + ds_sk (RANGE)."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-delta-")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "ds_pk", "KeyType": "HASH"},
                   {"AttributeName": "ds_sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "ds_pk", "AttributeType": "S"},
                              {"AttributeName": "ds_sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0, interval_s=2.0,
        description=f"delta table {name} reaching ACTIVE",
    )
    return name, resp["TableDescription"]["TableArn"]


def _one_error(body):
    """The single GraphQL error in ``body``, asserting there is exactly one."""
    errors = body.get("errors") or []
    assert len(errors) == 1, f"expected exactly one GraphQL error, got {errors!r}"
    return errors[0]


@tags("axis:rejection", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """OPTIMISTIC_CONCURRENCY refuses a stale versioned write and returns the live server item, the
    row in DynamoDB is left untouched, and after the item moves to version 2 the refusal payload
    moves with it.
    """
    svc = ctx.client("appsync")
    ddb = ctx.client("dynamodb")
    base_table, base_arn = _create_table(ctx)
    delta_table, delta_arn = _create_delta_table(ctx)

    role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem",
                                  "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
                       "Resource": [base_arn, base_arn + "/*", delta_arn, delta_arn + "/*"]}],
    })

    api_id, uris, _arn = _graphql_api(ctx, svc, SDL)
    graphql_uri = uris["GRAPHQL"]

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(
        apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB", serviceRoleArn=role_arn,
        dynamodbConfig={
            "tableName": base_table,
            "awsRegion": ctx.region,
            "versioned": True,
            "deltaSyncConfig": {
                "baseTableTTL": 0,
                "deltaSyncTableName": delta_table,
                "deltaSyncTableTTL": 60,
            },
        },
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    for field, template in (("putPost", VTL_PUT), ("bumpPost", VTL_BUMP)):
        svc.create_resolver(
            apiId=api_id, typeName="Mutation", fieldName=field,
            kind="UNIT", dataSourceName=ds_name,
            requestMappingTemplate=template, responseMappingTemplate=VTL_RESPONSE,
            syncConfig=SYNC_CONFIG,
        )
        ctx.on_cleanup(
            lambda _f=field: svc.delete_resolver(
                apiId=api_id, typeName="Mutation", fieldName=_f
            )
        )

    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync conflict key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))

    put = ("mutation Put($id: ID!, $title: String!, $expectedVersion: Int!) "
           "{ putPost(id: $id, title: $title, expectedVersion: $expectedVersion) "
           "{ id title _version } }")
    bump = ("mutation Bump($id: ID!, $title: String!, $expectedVersion: Int!) "
            "{ bumpPost(id: $id, title: $title, expectedVersion: $expectedVersion) "
            "{ id title _version } }")

    def _is_transient_role_assumption_error(res):
        """AppSync can transiently fail to assume its OWN service role well after that role's
        first successful use in this same run (measured on real AWS: the failure surfaced on the
        THIRD call, not the first), so this is IAM/AppSync-side eventual consistency, not a
        one-time propagation delay -- every call needs the guard, not just the first.
        """
        status, body = res
        errors = (body or {}).get("errors") or []
        return (
            status == 200 and len(errors) == 1
            and errors[0].get("errorType") == "Unauthorized"
            and "Unable to assume role" in (errors[0].get("message") or "")
        )

    def _gql(query, variables):
        return _poll_until(
            lambda: _post_json(ctx, graphql_uri, {"x-api-key": api_key},
                               {"query": query, "variables": variables}),
            lambda res: not _is_transient_role_assumption_error(res),
            timeout_s=60.0, interval_s=3.0,
            description="AppSync's assumption of its own DynamoDB service role to stop flapping",
        )

    post_id = ctx.unique_name("post-")
    title_a = ctx.unique_name("titleA-")
    title_b = ctx.unique_name("titleB-")
    refused_1 = ctx.unique_name("refusedONE-")
    refused_2 = ctx.unique_name("refusedTWO-")

    # ---- positive control leg, and the bounded retry at FIRST USE of the new role ----
    status, created = _poll_until(
        lambda: _gql(put, {"id": post_id, "title": title_a, "expectedVersion": 1}),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the versioned DynamoDB resolver to become invocable (IAM propagation)",
    )
    assert status == 200, f"the control write returned {status!r}: {created!r}"
    assert created["data"]["putPost"]["_version"] == 1, (
        f"a versioned data source must stamp the first write with _version 1: {created!r}"
    )
    assert created["data"]["putPost"]["title"] == title_a, (
        f"the control write did not store its own title: {created!r}"
    )
    seeded = ddb.get_item(
        TableName=base_table, Key={"id": {"S": post_id}}, ConsistentRead=True
    ).get("Item")
    assert seeded is not None and seeded["title"]["S"] == title_a, (
        f"the control write did not land in DynamoDB: {seeded!r}"
    )

    # ---- break exactly one thing: the identical mutation, now that the item EXISTS ----
    status, conflict = _gql(
        put, {"id": post_id, "title": refused_1, "expectedVersion": 1}
    )
    assert status == 200, (
        f"a conflict is reported inside a GraphQL 200, not at the transport; got {status!r}: "
        f"{conflict!r}"
    )
    error = _one_error(conflict)
    assert error.get("errorType") == "ConflictUnhandled", (
        f"the versioned write over an existing item was not refused by the conflict handler; "
        f"got errorType {error.get('errorType')!r} in {conflict!r}"
    )
    assert error.get("path") == ["putPost"], (
        f"the conflict error must name the field it refused: {error!r}"
    )
    server_item = error.get("data")
    assert isinstance(server_item, dict), (
        f"OPTIMISTIC_CONCURRENCY must hand the client the CURRENT server item so it can retry, "
        f"but the error carried no `data` object: {error!r}"
    )
    assert server_item.get("_version") == 1, (
        f"the refusal did not report the live server version 1: {server_item!r}"
    )
    assert server_item.get("title") == title_a, (
        f"the refusal's item is not the last successful write: {server_item!r}"
    )
    assert (conflict.get("data") or {}).get("putPost") is None, (
        f"the refused mutation returned data as well as a conflict: {conflict!r}"
    )

    # ---- the effect is absent, read out of DynamoDB with a typed key ----
    item = ddb.get_item(
        TableName=base_table, Key={"id": {"S": post_id}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, f"the item vanished from the base table: {post_id!r}"
    assert item["title"]["S"] == title_a, (
        f"the refused write reached the table anyway: {item!r} (it tried {refused_1!r}; the "
        f"last successful write was {title_a!r})"
    )
    assert item["_version"]["N"] == "1", (
        f"the refused write advanced the stored version: {item!r}"
    )

    # ---- a version-CHECKED update with the version the refusal reported does succeed ----
    status, bumped = _gql(
        bump, {"id": post_id, "title": title_b, "expectedVersion": server_item["_version"]}
    )
    assert status == 200 and not bumped.get("errors"), (
        f"an UpdateItem carrying the version the refusal handed back was also refused: "
        f"{status!r} {bumped!r}"
    )
    assert bumped["data"]["bumpPost"]["_version"] == 2, (
        f"a successful versioned write must increment _version to 2: {bumped!r}"
    )

    # ---- and the refusal's payload TRACKS the new server state, so it is not a constant ----
    status, conflict2 = _gql(
        put, {"id": post_id, "title": refused_2, "expectedVersion": 2}
    )
    assert status == 200, f"the second refusal did not come back as a 200: {status!r}"
    error2 = _one_error(conflict2)
    assert error2.get("errorType") == "ConflictUnhandled", (
        f"the second versioned write over the existing item was not refused: {conflict2!r}"
    )
    assert error2["data"]["_version"] == 2, (
        f"the refusal payload must be read from LIVE server state; after the update it still "
        f"reported {error2['data'].get('_version')!r} instead of 2: {error2!r}"
    )
    assert error2["data"]["title"] == title_b, (
        f"the refusal payload did not follow the item's new title: {error2['data']!r}"
    )

    final = ddb.get_item(
        TableName=base_table, Key={"id": {"S": post_id}}, ConsistentRead=True
    )["Item"]
    assert final["title"]["S"] == title_b, (
        f"the table does not hold the last SUCCESSFUL write: {final!r}"
    )
    assert final["_version"]["N"] == "2", (
        f"two refusals and one successful update must leave _version at 2: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
