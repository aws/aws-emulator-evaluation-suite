"""per-resolver-caching-keys-scope-cache-entries."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "per-resolver-caching-keys-scope-cache-entries"
GROUP = "server-side"
SERVICES = ["appsync"]

SDL = """schema { query: Query }
type Query {
    counted(id: ID!, noise: String!): Int
    uncounted(id: ID!, noise: String!): Int
}
"""

CACHE_TIMEOUT_S = 900.0
RESOLVER_TTL_S = 3600  # the maximum TTL; outlives the check so no leg misses by expiry

# Each resolver ADDs 1 to its OWN counter item and returns the post-increment value, so a real
# backend invocation leaves a durable trace that no cached response can fabricate.
JS_COUNTER = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'UpdateItem',
    key: util.dynamodb.toMapValues({ id: 'COUNTER_ID' }),
    update: {
      expression: 'ADD #v :inc',
      expressionNames: { '#v': 'value' },
      expressionValues: util.dynamodb.toMapValues({ ':inc': 1 }),
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
    """Detach/delete every policy first -- IAM refuses to delete a role that still has any."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(
                f"role {role_name} not deleted: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _create_role(ctx, trust_service, inline_policy):
    """An IAM role trusted by ``trust_service``, with its teardown registered.

    IAM exposes no condition reporting that a trust policy has become effective, so the
    bounded retry at first use absorbs propagation.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-cache-role-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return arn


def _create_counter_table(ctx, counter_ids):
    """An on-demand table seeded with one zeroed counter item per id."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-cachectr-")
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
    for cid in counter_ids:
        ddb.put_item(TableName=name, Item={"id": {"S": cid}, "value": {"N": "0"}})
    return name, arn


def _counter(ctx, table, counter_id):
    """The counter's CURRENT value, read at the destination through GetItem -- a different
    operation from the GraphQL POST that mutated it."""
    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"id": {"S": counter_id}}, ConsistentRead=True
    ).get("Item")
    assert item, (
        f"counter item {counter_id!r} is missing from {table!r}; the check seeded it, so this is "
        f"a lost write, not an absent prerequisite"
    )
    return int(item["value"]["N"])


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False, so a poll timeout names
    the code that kept it from settling."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _graphql_api(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + an ACTIVE schema + a key -> (api_id, uri, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
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
        f"schema creation did not succeed: expected SUCCESS/ACTIVE, got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav cache key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """cachingKeys decide the cache key: a non-key argument change hits, an id change misses, and
    under PER_RESOLVER_CACHING a resolver without cachingConfig is never cached.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/enabling-caching.html
    """
    svc = ctx.client("appsync")
    table, table_arn = _create_counter_table(ctx, ["counted", "uncounted"])
    role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
                       "Resource": [table_arn]}],
    })

    api_id, url, key = _graphql_api(ctx, svc, SDL)

    ds_name = _alnum(ctx, "ctr")
    _poll_until(
        lambda: _try(svc.create_data_source, apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB",
                     serviceRoleArn=role_arn,
                     dynamodbConfig={"tableName": table, "awsRegion": ctx.region}),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description="CreateDataSource to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    for field, counter_id, caching in (
        ("counted", "counted", {"ttl": RESOLVER_TTL_S, "cachingKeys": ["$context.arguments.id"]}),
        ("uncounted", "uncounted", None),
    ):
        kwargs = dict(
            apiId=api_id, typeName="Query", fieldName=field, kind="UNIT",
            dataSourceName=ds_name,
            runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
            code=JS_COUNTER.replace("COUNTER_ID", counter_id),
        )
        if caching is not None:
            kwargs["cachingConfig"] = caching
        svc.create_resolver(**kwargs)
        ctx.on_cleanup(
            lambda _f=field: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName=_f)
        )

    # The control plane must agree that only ONE resolver opted in -- otherwise the twin control
    # below is not a control at all.
    opted_in = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="counted")["resolver"]
    assert (opted_in.get("cachingConfig") or {}).get("cachingKeys") == [
        "$context.arguments.id"
    ], f"GetResolver lost the cachingKeys the check declared: {opted_in.get('cachingConfig')!r}"
    opted_out = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="uncounted")["resolver"]
    assert not opted_out.get("cachingConfig"), (
        f"the control resolver must declare NO cachingConfig, got "
        f"{opted_out.get('cachingConfig')!r}"
    )

    svc.create_api_cache(
        apiId=api_id, ttl=RESOLVER_TTL_S, apiCachingBehavior="PER_RESOLVER_CACHING", type="SMALL"
    )
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
    assert cache["apiCachingBehavior"] == "PER_RESOLVER_CACHING", (
        f"expected PER_RESOLVER_CACHING, got {cache['apiCachingBehavior']!r}"
    )

    id_a, id_b = ctx.unique_name("ida-"), ctx.unique_name("idb-")
    noise_1, noise_2 = ctx.unique_name("n1-"), ctx.unique_name("n2-")

    def _ask(field, ident, noise):
        query = (
            f"query Q($i: ID!, $n: String!) {{ {field}(id: $i, noise: $n) }}"
        )
        status, body = _post_json(
            ctx, url, {"x-api-key": key},
            {"query": query, "variables": {"i": ident, "n": noise}},
        )
        assert status == 200, f"{field}({ident!r},{noise!r}) did not return 200: {status!r} {body!r}"
        assert not body.get("errors"), (
            f"{field}({ident!r},{noise!r}) returned GraphQL errors: {body['errors']!r}"
        )
        value = (body.get("data") or {}).get(field)
        assert isinstance(value, int), (
            f"expected {field} to resolve to the post-increment counter integer, got {value!r} "
            f"in {body!r}"
        )
        return value

    # ---- warm the endpoint on the UNCACHED resolver, so warming cannot poison a cache entry --
    # A freshly created resolver and service role can answer 200-with-null for a few seconds, so
    # the warm-up polls the RAW response rather than going through _ask (which asserts).
    warm_query = "query W($i: ID!, $n: String!) { uncounted(id: $i, noise: $n) }"
    _poll_until(
        lambda: _post_json(ctx, url, {"x-api-key": key},
                           {"query": warm_query, "variables": {"i": id_a, "n": noise_1}}),
        lambda res: res[0] == 200 and isinstance((res[1].get("data") or {}).get("uncounted"), int),
        timeout_s=180.0, interval_s=5.0,
        description="the uncached resolver to reach DynamoDB through the live endpoint",
    )

    # ---- leg 1: first call for id_a -> MISS, the resolver runs exactly once ------------------
    before = _counter(ctx, table, "counted")
    first = _ask("counted", id_a, noise_1)
    after_first = _counter(ctx, table, "counted")
    assert after_first - before == 1, (
        f"the first call for id={id_a!r} must reach DynamoDB exactly once: expected the counter "
        f"to advance by 1 from {before}, got {after_first}"
    )

    # ---- leg 2: same caching key, DIFFERENT non-key argument -> HIT, delta 0 -----------------
    # Single shot by construction: a retry would increment the counter on a miss and make the
    # exact-count assertion unfalsifiable.
    second = _ask("counted", id_a, noise_2)
    after_second = _counter(ctx, table, "counted")
    assert after_second == after_first, (
        f"noise is NOT in cachingKeys, so changing it must hit the entry written for "
        f"id={id_a!r}: expected the counter to stay at {after_first}, got {after_second}"
    )
    assert second == first, (
        f"a cache hit must replay the cached response byte for byte: expected {first}, got "
        f"{second}"
    )

    # ---- leg 3: DIFFERENT caching key -> MISS, delta 1 --------------------------------------
    third = _ask("counted", id_b, noise_1)
    after_third = _counter(ctx, table, "counted")
    assert after_third - after_second == 1, (
        f"id IS in cachingKeys, so id={id_b!r} must miss and reach DynamoDB: expected the "
        f"counter to advance by 1 from {after_second}, got {after_third}"
    )
    assert third == after_third, (
        f"the missed call must return the value it just wrote: counter is {after_third}, the "
        f"response said {third}"
    )

    # ---- leg 4: twin control in the same instant -- the opted-out resolver is never cached ---
    ctr_before = _counter(ctx, table, "uncounted")
    u_first = _ask("uncounted", id_a, noise_1)
    u_second = _ask("uncounted", id_a, noise_1)
    ctr_after = _counter(ctx, table, "uncounted")
    assert ctr_after - ctr_before == 2, (
        f"under PER_RESOLVER_CACHING a resolver with no cachingConfig must never be cached: two "
        f"identical calls must both reach DynamoDB, so the counter must advance by 2 from "
        f"{ctr_before}, got {ctr_after}"
    )
    assert u_second == u_first + 1, (
        f"the second uncached call must observe its own increment: expected {u_first + 1}, got "
        f"{u_second}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
