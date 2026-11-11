"""deep-appsync-3-appsync-rt-operation-level-cache-separates-operation-names."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-3-appsync-rt-operation-level-cache-separates-operation-names"
GROUP = "data-plane"
SERVICES = ["appsync"]

SDL = """schema { query: Query }
type Query {
    plain(id: ID!): Int
}
"""

CACHE_TIMEOUT_S = 900.0
CACHE_TTL_S = 3600

# ONE counting resolver with NO cachingConfig: under OPERATION_LEVEL_CACHING the whole operation
# response is the cached unit, so resolver-level opt-in plays no part.
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

    IAM exposes no condition reporting that a trust policy has become effective, so the bounded
    CreateDataSource retry at FIRST USE is what waits for it, on every target alike.
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
    """How many times the backend has really been invoked for ``counter_id``, read at DynamoDB
    through GetItem -- a different operation from the GraphQL POST that mutated it. An absent
    item means zero invocations."""
    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"id": {"S": counter_id}}, ConsistentRead=True
    ).get("Item")
    return int(item["value"]["N"]) if item else 0


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- so a poll timeout names what kept it from
    settling."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _settle(fn, teardown) -> None:
    """Run a teardown call: NotFoundException means gone; ConcurrentModificationException (the
    API cache still deleting) is retried every 2 s to the shared deadline; anything else raises."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConcurrentModificationException" or time.monotonic() >= teardown.deadline():
                raise
        time.sleep(2)


def _graphql_api(ctx, svc, sdl, teardown):
    """Create an API_KEY GraphQL API + an ACTIVE schema + a key -> (api_id, uri, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-rtc-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: _settle(lambda: svc.delete_graphql_api(apiId=api_id), teardown))
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


def _provision_cache(ctx, svc, api_id, behavior, teardown):
    svc.create_api_cache(apiId=api_id, ttl=CACHE_TTL_S, apiCachingBehavior=behavior, type="SMALL")
    ctx.on_cleanup(lambda: _settle(lambda: svc.delete_api_cache(apiId=api_id), teardown))
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
    """OPERATION_LEVEL_CACHING keys on the operation name and variables: two documents differing only
    in operation name never share a cache entry, shown by DynamoDB invocation counters and a stale
    hit on the first operation after the second advanced the backend."""
    svc = ctx.client("appsync")
    teardown = _Teardown()
    table, table_arn = _create_counter_table(ctx)
    role_arn = _create_role(ctx, table_arn)
    api_id, url, key = _graphql_api(ctx, svc, SDL, teardown)
    ds_ctr = _counter_data_source(ctx, svc, api_id, table, role_arn)
    svc.create_resolver(apiId=api_id, typeName="Query", fieldName="plain", kind="UNIT",
                        dataSourceName=ds_ctr, runtime=APPSYNC_JS,
                        code=JS_COUNTER.replace("FIELD", "plain"))
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="plain"))
    opted = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="plain")["resolver"]
    assert not opted.get("cachingConfig"), (
        f"the counting resolver must declare NO cachingConfig, got {opted.get('cachingConfig')!r}"
    )

    _provision_cache(ctx, svc, api_id, "OPERATION_LEVEL_CACHING", teardown)
    # Each warm-up attempt uses a fresh id, so even a cached warm-up response cannot alias the
    # documents graded below.
    _warm(ctx, url, key, "plain", ctx.unique_name("warm-"))

    k = ctx.unique_name("k-")
    alpha = 'query Alpha { plain(id: "%s") }' % k
    beta = 'query Beta { plain(id: "%s") }' % k

    def _send(doc, variables=None):
        payload = {"query": doc}
        if variables is not None:
            payload["variables"] = variables
        status, body = _post_json(ctx, url, {"x-api-key": key}, payload)
        assert status == 200 and not body.get("errors"), (
            f"{doc!r} failed: {status!r} {body!r}"
        )
        value = (body.get("data") or {}).get("plain")
        assert isinstance(value, int), f"{doc!r} returned no integer: {body!r}"
        return value

    def _ctr(ident):
        return _counter(ctx, table, f"plain:{ident}")

    v = _send(alpha)
    assert (v, _ctr(k)) == (1, 1), (
        f"the first Alpha must miss and reach DynamoDB once: returned {v!r}, counter {_ctr(k)!r}"
    )
    v = _send(alpha)
    assert (v, _ctr(k)) == (1, 1), (
        f"the repeated Alpha must HIT (delta 0): returned {v!r}, counter {_ctr(k)!r}"
    )

    v = _send(beta)
    assert _ctr(k) == 2, (
        f"Beta differs from Alpha only by operation name and must NOT share Alpha's entry: "
        f"expected the counter to advance 1 -> 2, got {_ctr(k)!r} (returned {v!r})"
    )
    assert v == 2, f"Beta's miss must return the fresh count 2, got {v!r}"
    v = _send(beta)
    assert (v, _ctr(k)) == (2, 2), (
        f"the repeated Beta must HIT its own entry (delta 0): returned {v!r}, counter {_ctr(k)!r}"
    )

    v = _send(alpha)
    assert _ctr(k) == 2, (
        f"Alpha's entry must survive Beta's miss, so Alpha HITs (delta 0): counter {_ctr(k)!r}"
    )
    assert v == 1, (
        f"Alpha must replay its OWN stale entry (1) although the backend now reads 2, got {v!r}"
    )

    # ---- variables participate in the operation key ----------------------------------------
    var_doc = "query Alpha($i: ID!) { plain(id: $i) }"
    k2, k3 = ctx.unique_name("k2-"), ctx.unique_name("k3-")
    assert _send(var_doc, {"i": k2}) == 1 and _ctr(k2) == 1, (
        f"Alpha($i={k2!r}) must miss once: counter {_ctr(k2)!r}"
    )
    assert _send(var_doc, {"i": k2}) == 1 and _ctr(k2) == 1, (
        f"the identical Alpha($i={k2!r}) must HIT (delta 0): counter {_ctr(k2)!r}"
    )
    assert _send(var_doc, {"i": k3}) == 1 and _ctr(k3) == 1, (
        f"the same document with a NEW variable value must miss (counter for {k3!r} 0 -> 1): "
        f"counter {_ctr(k3)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
