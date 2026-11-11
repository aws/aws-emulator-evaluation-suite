"""deep-appsync-1-appsync-conflict-lambda-handler-reject-surfaces-conflictunhandled-and-item-unchanged."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-1-appsync-conflict-lambda-handler-reject-surfaces-conflictunhandled-and-item-unchanged"
GROUP = 'concurrency'
SERVICES = ['appsync', 'dynamodb', 'lambda']

SDL = """schema { query: Query mutation: Mutation }
type Post {
    id: ID!
    title: String
    resolvedBy: String
    _version: Int
    _lastChangedAt: AWSTimestamp
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    createPost(id: ID!, title: String!): Post
    setTitle(id: ID!, value: String!, expectedVersion: Int!): Post
}
"""

VTL_CREATE = """{
    "version": "2018-05-29",
    "operation": "PutItem",
    "key": {"id": $util.dynamodb.toDynamoDBJson($ctx.args.id)},
    "attributeValues": {"title": $util.dynamodb.toDynamoDBJson($ctx.args.title)},
    "_version": 1
}"""

# `expressionNames` is load-bearing on a versioned resolver: the bare `SET title = :x`
# form returns InternalFailure on the conflict path and NEVER invokes the conflict handler.
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

VTL_RESPONSE = """#if( $ctx.error )
    $util.error($ctx.error.message, $ctx.error.type, $ctx.result)
#end
$util.toJson($ctx.result)"""

FIELDS = "{ id title resolvedBy _version _lastChangedAt }"

RESOLVED_BY = "lambda-conflict-handler"

# The conflict handler. Every invocation is counted in a DynamoDB table the handler owns, keyed
# by the conflicting item's id, together with the full event AppSync sent -- an independent side
# channel, so "the handler ran" never rests on the GraphQL reply. Its role grants nothing but
# that one UpdateItem: in particular no logs:*, so no /aws/lambda/ log group can be created.
HANDLER = """import json
import os

import boto3

_ddb = boto3.client("dynamodb")


def handler(event, context):
    existing = event.get("existingItem") or {}
    new = event.get("newItem") or {}
    _ddb.update_item(
        TableName=os.environ["COUNTER_TABLE"],
        Key={"id": {"S": "inv#" + str(existing.get("id"))}},
        UpdateExpression="ADD n :one SET lastEvent = :ev",
        ExpressionAttributeValues={":one": {"N": "1"},
                                   ":ev": {"S": json.dumps(event, default=str)}},
    )
    if str(new.get("title", "")).startswith("reject-"):
        return {"action": "REJECT"}
    item = {k: v for k, v in new.items() if not k.startswith("_")}
    item["resolvedBy"] = os.environ["RESOLVED_BY"]
    return {"action": "RESOLVE", "item": item}
"""


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


def _versioned_dynamodb_api(ctx, sdl, extra_statements=()):
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
                       "Resource": [base_arn, base_arn + "/*", delta_arn, delta_arn + "/*"]},
                      *extra_statements],
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
        or (etype.startswith("Lambda:") and "not authorized to perform" in msg)
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


def _create_function(ctx, role_arn, code, env):
    """A python3.12 zip function; retries only Lambda's documented role-propagation refusal."""
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    name = ctx.unique_name("sim2real-behav-appsync-fn-")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))

    def attempt():
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": buf.getvalue()},
                Environment={"Variables": env}, Timeout=15, MemorySize=128,
                Description="sim2real behavioral appsync conflict handler",
                Tags={"sim2real": CHECK[:256], "sim2real:managed": "true"},
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "cannot be assumed" in (err.get("Message") or "")):
                return None
            raise

    created = _poll_until(attempt, lambda r: r is not None, timeout_s=120.0, interval_s=5.0,
                          description="Lambda to accept the new execution role")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0, interval_s=2.0,
        description=f"function {name} reaching Active",
    )
    return created["FunctionArn"]




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
    """A LAMBDA conflict handler is not invoked for a create or a current-version write. A stale
    write invokes it once with the live item; its REJECT surfaces ConflictUnhandled with the item
    unchanged, and its RESOLVE writes the handler's item and advances `_version`.
    """
    ddb = ctx.client("dynamodb")
    counter_table, counter_arn = _create_table(
        ctx, "sim2real-behav-appsync-cnt-", [("id", "HASH")]
    )
    fn_role = _create_role(ctx, "lambda.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
                       "Resource": [counter_arn]}],
    })
    fn_arn = _create_function(
        ctx, fn_role, HANDLER, {"COUNTER_TABLE": counter_table, "RESOLVED_BY": RESOLVED_BY}
    )
    svc, api_id, uri, ds_name, base_table, api_key = _versioned_dynamodb_api(
        ctx, SDL,
        extra_statements=[{"Effect": "Allow", "Action": ["lambda:InvokeFunction"],
                           "Resource": [fn_arn]}],
    )
    sync_config = {
        "conflictHandler": "LAMBDA",
        "conflictDetection": "VERSION",
        "lambdaConflictHandlerConfig": {"lambdaConflictHandlerArn": fn_arn},
    }
    for field, template in (("createPost", VTL_CREATE), ("setTitle", VTL_SET_TITLE)):
        svc.create_resolver(
            apiId=api_id, typeName="Mutation", fieldName=field,
            kind="UNIT", dataSourceName=ds_name,
            requestMappingTemplate=template, responseMappingTemplate=VTL_RESPONSE,
            syncConfig=sync_config,
        )
        ctx.on_cleanup(
            lambda _f=field: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName=_f)
        )
    gql = _gql_client(ctx, uri, api_key)

    post_id = ctx.unique_name("post-")
    title_seed = ctx.unique_name("seed-")
    title_v2 = ctx.unique_name("v2-")
    title_rejected = ctx.unique_name("reject-")
    title_resolved = ctx.unique_name("accept-")
    create = ("mutation C($id: ID!, $title: String!) "
              "{ createPost(id: $id, title: $title) %s }" % FIELDS)
    set_title = ("mutation S($id: ID!, $value: String!, $v: Int!) "
                 "{ setTitle(id: $id, value: $value, expectedVersion: $v) %s }" % FIELDS)

    def invocations():
        rec = _item(ddb, counter_table, "inv#" + post_id)
        if rec is None:
            return 0, None
        return int(rec["n"]["N"]), json.loads(rec["lastEvent"]["S"])

    seeded = _ok(_poll_until(
        lambda: gql(create, {"id": post_id, "title": title_seed}),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the versioned DynamoDB resolver to become invocable (IAM propagation)",
    ), "createPost")
    assert seeded["_version"] == 1, f"a versioned create must stamp _version 1: {seeded!r}"
    moved = _ok(gql(set_title, {"id": post_id, "value": title_v2, "v": 1}), "setTitle")
    assert moved["_version"] == 2 and moved["title"] == title_v2, (
        f"a current-version write must apply directly and reach v2: {moved!r}"
    )
    count, _ = invocations()
    assert count == 0, (
        f"the conflict handler must not run when there is no conflict; it ran {count!r} times"
    )
    before = _item(ddb, base_table, post_id)
    assert before is not None and before["_version"]["N"] == "2", (
        f"the v2 item is not in DynamoDB: {before!r}"
    )

    status, refused = gql(set_title, {"id": post_id, "value": title_rejected, "v": 1})
    assert status == 200, (
        f"a conflict is reported inside a GraphQL 200, not at the transport; got {status!r}: "
        f"{refused!r}"
    )
    error = _one_error(refused)
    assert error.get("errorType") == "ConflictUnhandled", (
        f"the handler's REJECT must surface as ConflictUnhandled; got "
        f"{error.get('errorType')!r} in {refused!r}"
    )
    assert error.get("message") == "Conflict resolver rejects mutation.", (
        f"the REJECT refusal carries the wrong message: {error.get('message')!r} in {refused!r}"
    )
    assert error.get("path") == ["setTitle"], f"the refusal must name its field: {error!r}"
    assert (refused.get("data") or {}).get("setTitle") is None, (
        f"the rejected mutation returned data as well as a conflict: {refused!r}"
    )
    server_item = error.get("data")
    assert isinstance(server_item, dict), f"the refusal carried no server item: {error!r}"
    assert server_item.get("_version") == 2 and server_item.get("title") == title_v2, (
        f"the refusal's item is not the live v2 row: {server_item!r}"
    )

    count, event = invocations()
    assert count == 1, (
        f"a stale write must invoke the conflict handler exactly once; counted {count!r}"
    )
    assert (event.get("existingItem") or {}).get("_version") == 2, (
        f"the handler was not handed the live v2 server item: {event!r}"
    )
    assert (event.get("existingItem") or {}).get("title") == title_v2, (
        f"the handler's existingItem is not the server row: {event!r}"
    )
    assert (event.get("newItem") or {}).get("title") == title_rejected, (
        f"the handler's newItem does not carry the client's write: {event!r}"
    )
    assert (event.get("arguments") or {}).get("expectedVersion") == 1, (
        f"the handler's arguments are not the mutation's: {event!r}"
    )
    resolver = event.get("resolver") or {}
    assert (resolver.get("parentType"), resolver.get("field"), resolver.get("tableName")) == (
        "Mutation", "setTitle", base_table
    ), f"the handler's resolver context is wrong: {resolver!r}"

    after = _item(ddb, base_table, post_id)
    assert after == before, (
        f"the REJECTed write changed the row: before {before!r}, after {after!r}"
    )

    # Positive control: same stale version, only the handler's verdict differs.
    resolved = _ok(gql(set_title, {"id": post_id, "value": title_resolved, "v": 1}), "setTitle")
    assert resolved["title"] == title_resolved and resolved["resolvedBy"] == RESOLVED_BY, (
        f"RESOLVE must write the HANDLER's item (marked resolvedBy): {resolved!r}"
    )
    assert resolved["_version"] == 3, f"the RESOLVEd write must advance _version to 3: {resolved!r}"
    count, event = invocations()
    assert count == 2, f"the second stale write must be the handler's second call; counted {count!r}"
    stored = _item(ddb, base_table, post_id)
    assert stored["title"]["S"] == title_resolved, f"RESOLVE did not reach DynamoDB: {stored!r}"
    assert stored.get("resolvedBy", {}).get("S") == RESOLVED_BY, (
        f"the stored row is not the handler's item: {stored!r}"
    )
    assert stored["_version"]["N"] == "3", f"DynamoDB _version is not 3: {stored!r}"


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
