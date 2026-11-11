"""deep-appsync-1-appsync-conflict-automerge-concurrent-stale-writers-all-merge-with-distinct-versions."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-1-appsync-conflict-automerge-concurrent-stale-writers-all-merge-with-distinct-versions"
GROUP = 'concurrency'
SERVICES = ['appsync', 'dynamodb']

ATTRS = ("alpha", "beta", "gamma")

SDL = """schema { query: Query mutation: Mutation }
type Post {
    id: ID!
    title: String
    alpha: String
    beta: String
    gamma: String
    _version: Int
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    createPost(id: ID!, title: String!): Post
    setAttr(id: ID!, attr: String!, value: String!, expectedVersion: Int!): Post
}
"""

VTL_CREATE = """{
    "version": "2018-05-29",
    "operation": "PutItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "attributeValues": {"title": $util.dynamodb.toDynamoDBJson($ctx.args.title)},
    "_version": 1
}"""

# One resolver, attribute chosen by argument. `expressionNames` is load-bearing on the conflict
# path. The schema exposes only title/alpha/beta/gamma, and the check only ever passes those names.
VTL_SET_ATTR = """{
    "version": "2018-05-29",
    "operation": "UpdateItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "update": {
        "expression": "SET #a = :v",
        "expressionNames": {"#a": $util.toJson($ctx.args.attr)},
        "expressionValues": {":v": $util.dynamodb.toDynamoDBJson($ctx.args.value)}
    },
    "_version": $util.toJson($ctx.args.expectedVersion)
}"""

VTL_RESPONSE = """#if( $ctx.error )
    $util.error($ctx.error.message, $ctx.error.type, $ctx.result)
#end
$util.toJson($ctx.result)"""

SYNC_CONFIG = {"conflictHandler": "AUTOMERGE", "conflictDetection": "VERSION"}

FIELDS = "{ id title alpha beta gamma _version }"


# ===== helpers =====


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


# ===== end helpers =====


@tags("concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """Concurrent stale AUTOMERGE writers on disjoint attributes all merge, each stamped with a
    distinct `_version`, and the merged DynamoDB row holds every write: no stale writer is lost,
    whatever order the service serialises them in.
    """
    ddb = ctx.client("dynamodb")
    svc, api_id, uri, ds_name, base_table, api_key = _versioned_dynamodb_api(ctx, SDL)
    for field, template in (("createPost", VTL_CREATE), ("setAttr", VTL_SET_ATTR)):
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
    create = ("mutation C($id: ID!, $title: String!) "
              "{ createPost(id: $id, title: $title) %s }" % FIELDS)
    set_attr = ("mutation S($id: ID!, $attr: String!, $value: String!, $v: Int!) "
                "{ setAttr(id: $id, attr: $attr, value: $value, expectedVersion: $v) %s }"
                % FIELDS)
    seeded = _ok(_poll_until(
        lambda: gql(create, {"id": post_id, "title": ctx.unique_name("seed-")}),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the versioned DynamoDB resolver to become invocable (IAM propagation)",
    ), "createPost")
    assert seeded["_version"] == 1, f"a versioned create must stamp _version 1: {seeded!r}"
    title_v2 = ctx.unique_name("v2-")
    moved = _ok(gql(set_attr, {"id": post_id, "attr": "title", "value": title_v2, "v": 1}),
                "setAttr")
    assert moved["_version"] == 2, f"a current-version write must reach v2: {moved!r}"

    # ---- three writers, all holding the same STALE _version 1, fired at once ----
    values = {attr: ctx.unique_name(attr + "-") for attr in ATTRS}

    def writer(attr):
        return _ok(gql(set_attr, {"id": post_id, "attr": attr, "value": values[attr], "v": 1}),
                   "setAttr")

    with ThreadPoolExecutor(max_workers=len(ATTRS)) as pool:
        results = dict(zip(ATTRS, pool.map(writer, ATTRS)))

    for attr, res in results.items():
        assert res[attr] == values[attr], (
            f"concurrent stale writer {attr!r} was not merged into its own response: {res!r}"
        )
        assert res["title"] == title_v2, (
            f"concurrent writer {attr!r}'s merge lost the server's v2 title: {res!r}"
        )
    versions = sorted(r["_version"] for r in results.values())
    assert versions == [3, 4, 5], (
        f"three merged writes after v2 must be stamped 3, 4 and 5 -- each exactly once; got "
        f"{versions!r} from {results!r}"
    )

    stored = ddb.get_item(
        TableName=base_table, Key={"id": {"S": post_id}}, ConsistentRead=True
    ).get("Item")
    assert stored is not None, f"the row vanished: {post_id!r}"
    for attr in ATTRS:
        assert stored.get(attr, {}).get("S") == values[attr], (
            f"concurrent stale writer {attr!r} was LOST from the stored row: {stored!r}"
        )
    assert stored["title"]["S"] == title_v2, f"the v2 title did not survive: {stored!r}"
    assert stored["_version"]["N"] == "5", (
        f"DynamoDB _version {stored['_version']!r} != 5 (seed + 1 direct + 3 merged)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
