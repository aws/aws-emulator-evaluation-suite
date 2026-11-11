"""deep-appsync-3-appsync-rt-evict-from-api-cache-spares-sibling-key."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-3-appsync-rt-evict-from-api-cache-spares-sibling-key"
GROUP = "data-plane"
SERVICES = ["appsync"]

SDL = """schema { query: Query mutation: Mutation }
type Query {
    counted(id: ID!): Int
    plain(id: ID!): Int
}
type Mutation {
    evict(id: ID!): ID
    evictOtherField(id: ID!): ID
    evictShorthandKey(id: ID!): ID
}
"""

CACHE_TIMEOUT_S = 900.0
CACHE_TTL_S = 3600

# Each read ADDs 1 to an item keyed by (field, id) and returns the post-increment value, so every
# real backend invocation leaves a durable trace a cached response cannot fabricate.
JS_COUNTER = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'UpdateItem',
    key: util.dynamodb.toMapValues({ id: 'FIELD:' + ctx.args.id }),
    update: {
      expression: 'ADD #v :one',
      expressionNames: { '#v': 'value' },
      expressionValues: util.dynamodb.toMapValues({ ':one': 1 }),
    },
  };
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  return ctx.result.value;
}
"""

# The eviction runs in a mutation's RESPONSE handler on a NONE data source. KEY is the caching key
# exactly as the resolver's cachingKeys declare it, minus the leading '$'.
JS_EVICT = """import { extensions } from '@aws-appsync/utils';

export function request(ctx) {
  return { payload: ctx.args.id };
}

export function response(ctx) {
  extensions.evictFromApiCache('Query', 'TARGET_FIELD', { 'KEY_NAME': ctx.args.id });
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}




def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
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
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
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
    """Delete every inline policy first -- IAM refuses to delete a role that still has any."""
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(
                f"role {role_name} not deleted: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _create_role(ctx, table_arn):
    """An AppSync-trusted role allowed to UpdateItem on the counter table only.

    IAM reports no point at which a trust policy is effective; the CreateDataSource retry waits.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-rtc-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "appsync.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="counter-update",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
                           "Resource": [table_arn]}],
        }),
    )
    return arn


def _create_counter_table(ctx):
    """An on-demand table; resolvers ADD into one item per (field, id), created on first ADD."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-rtc-")
    arn = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0, interval_s=3.0,
        description=f"DynamoDB table {name} reaching ACTIVE",
    )
    return name, arn


def _counter(ctx, table, counter_id):
    """How many times the backend has really been invoked for ``counter_id``, read via GetItem.

    An absent item means zero invocations."""
    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"id": {"S": counter_id}}, ConsistentRead=True
    ).get("Item")
    return int(item["value"]["N"]) if item else 0


def _try(fn, **kwargs):
    """The call's result, or the AWS error code, so a poll timeout names the blocker."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _graphql_api(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + an ACTIVE schema + a key -> (api_id, uri, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-rtc-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav rt cache key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key


def _counter_data_source(ctx, svc, api_id, table, role_arn):
    name = _alnum(ctx, "ctr")
    _poll_until(
        lambda: _try(svc.create_data_source, apiId=api_id, name=name, type="AMAZON_DYNAMODB",
                     serviceRoleArn=role_arn,
                     dynamodbConfig={"tableName": table, "awsRegion": ctx.region}),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description="CreateDataSource to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=name))
    return name


def _provision_cache(ctx, svc, api_id, behavior):
    svc.create_api_cache(apiId=api_id, ttl=CACHE_TTL_S, apiCachingBehavior=behavior, type="SMALL")
    ctx.on_cleanup(lambda: svc.delete_api_cache(apiId=api_id))
    cache = _poll_until(
        lambda: svc.get_api_cache(apiId=api_id)["apiCache"],
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=CACHE_TIMEOUT_S, interval_s=15.0,
        description="the api cache reaching AVAILABLE",
    )
    assert cache["status"] == "AVAILABLE", (
        f"the api cache did not become usable: expected AVAILABLE, got {cache['status']!r} "
        f"({cache!r})"
    )
    assert cache["apiCachingBehavior"] == behavior, (
        f"expected {behavior}, got {cache['apiCachingBehavior']!r}"
    )


def _warm(ctx, url, key, field, nonce):
    """Poll an UNCACHED (or uniquely-keyed) read until the fresh resolver/role reach DynamoDB.
    A brand-new resolver and service role can answer 200-with-null for a few seconds."""
    query = f"query Warm($i: ID!) {{ {field}(id: $i) }}"
    counter = {"n": 0}

    def _probe():
        counter["n"] += 1
        return _post_json(ctx, url, {"x-api-key": key},
                          {"query": query, "variables": {"i": f"{nonce}-{counter['n']}"}})

    _poll_until(
        _probe,
        lambda res: res[0] == 200 and isinstance((res[1].get("data") or {}).get(field), int),
        timeout_s=180.0, interval_s=5.0,
        description=f"{field} to reach DynamoDB through the live endpoint",
    )




@tags("axis:negative-delivery", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """evictFromApiCache removes exactly the named (type, field, key) entry and nothing else.

    A shorthand key or the wrong field evicts nothing; sibling key B stays cached (via a counter).
    """
    svc = ctx.client("appsync")
    table, table_arn = _create_counter_table(ctx)
    role_arn = _create_role(ctx, table_arn)
    api_id, url, key = _graphql_api(ctx, svc, SDL)
    ds_ctr = _counter_data_source(ctx, svc, api_id, table, role_arn)
    ds_none = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "none"), type="NONE")[
        "dataSource"]["name"]
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_none))

    resolvers = [
        ("Query", "counted", ds_ctr, JS_COUNTER.replace("FIELD", "counted"),
         {"ttl": CACHE_TTL_S, "cachingKeys": ["$context.arguments.id"]}),
        ("Query", "plain", ds_ctr, JS_COUNTER.replace("FIELD", "plain"), None),
        ("Mutation", "evict", ds_none,
         JS_EVICT.replace("TARGET_FIELD", "counted").replace("KEY_NAME", "context.arguments.id"),
         None),
        ("Mutation", "evictOtherField", ds_none,
         JS_EVICT.replace("TARGET_FIELD", "plain").replace("KEY_NAME", "context.arguments.id"),
         None),
        ("Mutation", "evictShorthandKey", ds_none,
         JS_EVICT.replace("TARGET_FIELD", "counted").replace("KEY_NAME", "ctx.args.id"),
         None),
    ]
    for type_name, field, ds, code, caching in resolvers:
        kwargs = dict(apiId=api_id, typeName=type_name, fieldName=field, kind="UNIT",
                      dataSourceName=ds, runtime=APPSYNC_JS, code=code)
        if caching is not None:
            kwargs["cachingConfig"] = caching
        svc.create_resolver(**kwargs)
        ctx.on_cleanup(lambda _t=type_name, _f=field: svc.delete_resolver(
            apiId=api_id, typeName=_t, fieldName=_f))

    _provision_cache(ctx, svc, api_id, "PER_RESOLVER_CACHING")
    _warm(ctx, url, key, "plain", ctx.unique_name("warm-"))

    id_a, id_b = ctx.unique_name("ida-"), ctx.unique_name("idb-")

    def _ask(ident):
        status, body = _post_json(ctx, url, {"x-api-key": key},
                                  {"query": "query Q($i: ID!) { counted(id: $i) }",
                                   "variables": {"i": ident}})
        assert status == 200 and not body.get("errors"), (
            f"counted({ident!r}) failed: {status!r} {body!r}"
        )
        value = (body.get("data") or {}).get("counted")
        assert isinstance(value, int), f"counted({ident!r}) returned no integer: {body!r}"
        return value

    def _mutate(field, ident):
        status, body = _post_json(ctx, url, {"x-api-key": key},
                                  {"query": f"mutation E($i: ID!) {{ {field}(id: $i) }}",
                                   "variables": {"i": ident}})
        assert status == 200, f"{field}({ident!r}) did not return 200: {status!r} {body!r}"
        return body

    def _ctr(ident):
        return _counter(ctx, table, f"counted:{ident}")

    # Populate both entries: one miss each, then one hit each.
    a1, b1 = _ask(id_a), _ask(id_b)
    assert (_ctr(id_a), _ctr(id_b)) == (1, 1), (
        f"each first read must reach DynamoDB exactly once: counters (A, B) = "
        f"{(_ctr(id_a), _ctr(id_b))!r}"
    )
    assert (a1, b1) == (1, 1), f"first reads must return the fresh count 1: got {(a1, b1)!r}"
    a2, b2 = _ask(id_a), _ask(id_b)
    assert (_ctr(id_a), _ctr(id_b)) == (1, 1), (
        f"the second reads must both HIT (delta 0): counters (A, B) = "
        f"{(_ctr(id_a), _ctr(id_b))!r}"
    )
    assert (a2, b2) == (1, 1), f"hits must replay the cached value 1: got {(a2, b2)!r}"

    # The resolver-code shorthand 'ctx.args.id' is not the declared caching key; AWS answers
    # 'Invalid caching key ctx.args.id' inside the GraphQL response.
    bad = _mutate("evictShorthandKey", id_a)
    messages = [e.get("message") for e in bad.get("errors") or []]
    assert messages == ["Invalid caching key ctx.args.id"], (
        f"evictFromApiCache with key 'ctx.args.id' must be refused with exactly "
        f"'Invalid caching key ctx.args.id'; got errors {messages!r} in {bad!r}"
    )
    assert "apiCacheEntriesDeleted" not in (bad.get("extensions") or {}), (
        f"a refused eviction must report no deleted entries: {bad!r}"
    )
    assert _ask(id_a) == 1 and _ctr(id_a) == 1, (
        f"after the refused eviction A must still HIT: counter={_ctr(id_a)!r}"
    )

    # Right key form, wrong (uncached) field: no apiCacheEntriesDeleted in the extensions.
    other = _mutate("evictOtherField", id_a)
    assert not other.get("errors"), f"evictOtherField itself failed: {other!r}"
    assert (other.get("data") or {}).get("evictOtherField") == id_a, (
        f"evictOtherField did not resolve through its handler: {other!r}"
    )
    assert "apiCacheEntriesDeleted" not in (other.get("extensions") or {}), (
        f"evicting Query.plain must delete no Query.counted entry: {other!r}"
    )
    assert _ask(id_a) == 1 and _ctr(id_a) == 1, (
        f"after evicting a different field A must still HIT: counter={_ctr(id_a)!r}"
    )

    # Evicting A reports apiCacheEntriesDeleted == 1; A reaches DynamoDB, B returns its stale value.
    ev = _mutate("evict", id_a)
    assert not ev.get("errors"), f"the eviction mutation failed: {ev!r}"
    assert (ev.get("extensions") or {}).get("apiCacheEntriesDeleted") == 1, (
        f"evicting one cached key must report apiCacheEntriesDeleted == 1; got "
        f"extensions={ev.get('extensions')!r}"
    )
    a_after = _ask(id_a)
    assert _ctr(id_a) == 2, (
        f"after eviction the re-query of A must reach DynamoDB (delta +1 from 1); counter is "
        f"{_ctr(id_a)!r}"
    )
    assert a_after == 2, f"the evicted key must return the fresh count 2, got {a_after!r}"
    b_after = _ask(id_b)
    assert _ctr(id_b) == 1, (
        f"sibling key B was not evicted, so it must still HIT (delta 0); counter is "
        f"{_ctr(id_b)!r}"
    )
    assert b_after == 1, f"B must replay its cached value 1, got {b_after!r}"

    # A's re-query repopulated the entry, so the next read is a hit.
    assert _ask(id_a) == 2 and _ctr(id_a) == 2, (
        f"A's post-eviction read must have repopulated the entry, so this read HITs: "
        f"counter={_ctr(id_a)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
