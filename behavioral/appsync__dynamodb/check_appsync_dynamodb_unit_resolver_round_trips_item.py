"""appsync-dynamodb-unit-resolver-round-trips-item."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-dynamodb-unit-resolver-round-trips-item"
GROUP = 'data-plane'
SERVICES = ['appsync', 'dynamodb']

SDL = """schema { query: Query mutation: Mutation }
type Post {
    id: ID!
    title: String
    views: Int
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    putPost(id: ID!, title: String!, views: Int!): Post
    deletePost(id: ID!): Post
}
"""

JS_PUT = """import * as ddb from '@aws-appsync/utils/dynamodb';

export function request(ctx) {
  const { id, title, views } = ctx.args;
  return ddb.put({ key: { id }, item: { title, views } });
}

export function response(ctx) {
  return ctx.result;
}
"""

JS_GET = """import * as ddb from '@aws-appsync/utils/dynamodb';

export function request(ctx) {
  return ddb.get({ key: { id: ctx.args.id } });
}

export function response(ctx) {
  return ctx.result;
}
"""

JS_DELETE = """import * as ddb from '@aws-appsync/utils/dynamodb';

export function request(ctx) {
  return ddb.remove({ key: { id: ctx.args.id } });
}

export function response(ctx) {
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


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


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _post_json(url, headers, payload, timeout_s=30, verify=True):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(verify)) as resp:
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
    """IAM roles need every attached + inline policy removed before deletion; only an
    already-gone role (NoSuchEntity) is tolerated."""
    iam = ctx.client("iam")

    def _delete():
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)

    _tolerant(_delete, "NoSuchEntity")()


def _create_role(ctx, trust_service, inline_policy):
    """Create an IAM role trusted by ``trust_service`` and register its teardown.

    IAM exposes no condition reporting that a trust policy has become effective, so there is
    nothing to poll for here. Propagation is waited out entirely by the bounded retry at FIRST
    USE of the permission (see the mutation poll in ``run``), never by a bare sleep here.
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
    return resp["Role"]["Arn"], role_name


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
    ctx.on_cleanup(_tolerant(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
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
    ctx.on_cleanup(_tolerant(lambda: svc.delete_graphql_api(apiId=api_id), "NotFoundException"))
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


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c3")
def run(ctx) -> None:
    """An APPSYNC_JS DynamoDB resolver writes, reads and deletes the item for real: the GraphQL Int
    is stored as DynamoDB N "42", reads back as 42, and the item is gone after deletePost."""
    svc = ctx.client("appsync")
    ddb = ctx.client("dynamodb")
    table, table_arn = _create_table(ctx)

    role_arn, role_name = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem"],
                       "Resource": [table_arn, table_arn + "/*"]}],
    })

    api_id, uris, _arn = _graphql_api(ctx, svc, SDL)
    graphql_uri, route_headers = ctx.endpoint_route(uris["GRAPHQL"])

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(
        apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB",
        serviceRoleArn=role_arn,
        dynamodbConfig={"tableName": table, "awsRegion": ctx.region},
    )
    ctx.on_cleanup(_tolerant(lambda: svc.delete_data_source(apiId=api_id, name=ds_name), "NotFoundException"))

    for type_name, field, code in (
        ("Mutation", "putPost", JS_PUT), ("Query", "getPost", JS_GET), ("Mutation", "deletePost", JS_DELETE),
    ):
        svc.create_resolver(
            apiId=api_id, typeName=type_name, fieldName=field,
            kind="UNIT", dataSourceName=ds_name, runtime=APPSYNC_JS, code=code,
        )
        ctx.on_cleanup(_tolerant(
            lambda _t=type_name, _f=field: svc.delete_resolver(
                apiId=api_id, typeName=_t, fieldName=_f
            ),
            "NotFoundException",
        ))

    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync ddb resolver key"
    )["apiKey"]["id"]
    ctx.on_cleanup(_tolerant(lambda: svc.delete_api_key(apiId=api_id, id=api_key), "NotFoundException"))

    post_id = ctx.unique_name("post-")
    title = ctx.unique_name("title-")
    mutation = (
        "mutation Put($id: ID!, $title: String!, $views: Int!) "
        "{ putPost(id: $id, title: $title, views: $views) { id title views } }"
    )

    # While the new data-source role propagates, AppSync answers 200 with a null putPost and no
    # errors, so the first use retries until the mutated field is non-null.
    def _put_ready(res):
        status, body = res
        if status != 200:
            return False
        body = body or {}
        if body.get("errors"):
            return False
        return (body.get("data") or {}).get("putPost") is not None

    seen = []

    def _post_mutation():
        res = _post_json(graphql_uri, {"x-api-key": api_key, **route_headers},
                         {"query": mutation,
                          "variables": {"id": post_id, "title": title, "views": 42}},
                         verify=ctx.http_verify)
        seen.append(res[0])
        return res

    try:
        status, wrote = _poll_until(
            _post_mutation,
            _put_ready,
            timeout_s=150.0, interval_s=5.0,
            description="the DynamoDB resolver to become invocable (IAM propagation)",
        )
    except AssertionError as exc:
        if all(s is None for s in seen):
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: nothing answered at the GraphQL endpoint {graphql_uri} "
                f"within 150s, so the DynamoDB unit resolver could not be invoked at all"
            ) from exc
        raise
    assert status == 200, f"the mutation returned {status!r}: {wrote!r}"
    assert wrote["data"]["putPost"]["views"] == 42, (
        f"the mutation's own response lost the Int: {wrote!r}"
    )

    item = ddb.get_item(
        TableName=table, Key={"id": {"S": post_id}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, (
        f"the GraphQL mutation returned data but DynamoDB has no item for {post_id!r} -- the "
        f"resolver did not perform a real PutItem"
    )
    assert item["title"]["S"] == title, (
        f"AppSync wrote the wrong title into DynamoDB: {item!r}"
    )
    assert item["views"]["N"] == "42", (
        f"the GraphQL Int was not stored as a DynamoDB N: {item!r}"
    )

    query = "query Get($id: ID!) { getPost(id: $id) { id title views } }"
    q_status, queried = _post_json(
        graphql_uri, {"x-api-key": api_key, **route_headers},
        {"query": query, "variables": {"id": post_id}},
        verify=ctx.http_verify,
    )
    assert q_status == 200, f"the query returned {q_status!r}: {queried!r}"
    assert queried.get("errors") is None, f"the query returned errors: {queried['errors']!r}"
    assert queried["data"]["getPost"]["title"] == title, (
        f"the query through the resolver returned {queried['data']!r}"
    )
    assert queried["data"]["getPost"]["views"] == 42, (
        f"the Int round trip broke on the way back out -- a dict like {{'N': '42'}} here means "
        f"the DynamoDB attribute-value form leaked through the resolver: "
        f"{queried['data']['getPost']!r}"
    )

    removal = "mutation Del($id: ID!) { deletePost(id: $id) { id } }"
    d_status, deleted = _post_json(
        graphql_uri, {"x-api-key": api_key, **route_headers},
        {"query": removal, "variables": {"id": post_id}},
        verify=ctx.http_verify,
    )
    assert d_status == 200, f"the deletePost mutation returned {d_status!r}: {deleted!r}"
    assert deleted.get("errors") is None, f"the deletePost mutation returned errors: {deleted['errors']!r}"

    gone = ddb.get_item(TableName=table, Key={"id": {"S": post_id}}, ConsistentRead=True)
    assert "Item" not in gone, (
        f"deletePost returned without errors but DynamoDB still holds the item: {gone.get('Item')!r}"
    )

    a_status, after = _post_json(
        graphql_uri, {"x-api-key": api_key, **route_headers},
        {"query": query, "variables": {"id": post_id}},
        verify=ctx.http_verify,
    )
    assert a_status == 200, f"the query after delete returned {a_status!r}: {after!r}"
    assert after.get("errors") is None, f"the query after delete returned errors: {after['errors']!r}"
    assert "data" in after and after["data"].get("getPost", "absent") is None, (
        f"expected data.getPost == null for the deleted item, got {after.get('data')!r}"
    )

    # Tear down in reverse dependency order and prove each resource family gone. Deleting the
    # API removes its data source, resolvers and API key with it.
    _gone_graphql_api(ctx, api_id)
    _gone_table(ctx, table, {"id": {"S": post_id}})
    _gone_role(ctx, role_name)


# ===== teardown proofs (GONE: three beats per family) =====
#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message {msg!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_graphql_api(ctx, api_id: str) -> None:
    svc = ctx.client("appsync")
    svc.delete_graphql_api(apiId=api_id)
    nf = ("NotFoundException",)
    _poll_refused(lambda: svc.get_graphql_api(apiId=api_id), nf, 404, f"GetGraphqlApi {api_id}", "API not found.")
    listed = {a["apiId"] for a in _paged(svc, "list_graphql_apis", "graphqlApis")}
    assert api_id not in listed, f"ListGraphqlApis still lists deleted API {api_id}"
    _refused(lambda: svc.create_api_key(apiId=api_id), nf, 404, f"CreateApiKey {api_id}", "API not found.")


def _gone_table(ctx, name: str, item: dict) -> None:
    ddb = ctx.client("dynamodb")
    ddb.delete_table(TableName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: ddb.describe_table(TableName=name), nf, 400, f"DescribeTable {name}",
                  f"Requested resource not found: Table: {name} not found")
    assert name not in _paged(ddb, "list_tables", "TableNames"), f"ListTables still lists deleted table {name}"
    _refused(lambda: ddb.put_item(TableName=name, Item=item), nf, 400, f"PutItem {name}",
             "Requested resource not found")


def _gone_role(ctx, name: str, path: str = "/sim2real/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}",
                  f"The role with name {name} cannot be found.")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", f"The role with name {name} cannot be found.",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
