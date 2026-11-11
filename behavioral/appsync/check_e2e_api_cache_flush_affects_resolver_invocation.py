"""e2e-api-cache-flush-affects-resolver-invocation."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "e2e-api-cache-flush-affects-resolver-invocation"
GROUP = "server-side"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """FlushApiCache makes the next identical query bypass the cache and re-invoke the
    underlying resolver, mutating the backing store again, rather than merely resetting
    cache status metadata."""
    run_start = time.monotonic()
    dynamodb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    appsync = ctx.client("appsync")

    table_name, role_arn, api, api_key = _build_counter_api(ctx, dynamodb, iam, appsync)
    api_id = api["apiId"]
    graphql_url = api["uris"]["GRAPHQL"]

    cache = appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    assert cache["ttl"] == 300 and cache["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"expected ttl=300/FULL_REQUEST_CACHING from CreateApiCache, got {cache!r}"
    )
    setup_elapsed = time.monotonic() - run_start
    remaining_budget = max(30.0, 900.0 - setup_elapsed)
    _wait_cache_status(ctx, appsync, api_id, "AVAILABLE", timeout_s=remaining_budget)
    got = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert got["status"] == "AVAILABLE" and got["ttl"] == 300, (
        f"expected AVAILABLE/ttl=300 from an independent GetApiCache read, got {got!r}"
    )

    query = "query { increment }"
    first = _graphql_call(ctx, graphql_url, api_key, query)
    assert "errors" not in first, first
    first_value = first["data"]["increment"]

    # Cache hit: identical query, backing counter must NOT have been re-invoked.
    second = _graphql_call(ctx, graphql_url, api_key, query)
    assert "errors" not in second, second
    second_value = second["data"]["increment"]
    assert second_value == first_value, (
        f"expected cache hit to replay the exact cached response ({first_value}), got {second_value}"
    )

    appsync.flush_api_cache(apiId=api_id)

    # Cache miss after flush: the resolver must run again against DynamoDB, so the
    # counter genuinely advances (not just a metadata reset that fakes the same result).
    third = _wait_post_flush_increment(ctx, graphql_url, api_key, query, second_value, timeout_s=60)
    assert third == second_value + 1, f"expected the post-flush query to re-invoke the resolver, got {third}"


def _build_counter_api(ctx, dynamodb, iam, appsync):
    table_name = ctx.unique_name("sim2real-appsync-cache-ctr-")
    dynamodb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=table_name))
    dynamodb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    dynamodb.put_item(TableName=table_name, Item={"id": {"S": "counter"}, "value": {"N": "0"}})
    table_arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]

    role_name = ctx.unique_name("sim2real-appsync-cache-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:UpdateItem", "Resource": table_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="ddb-access", PolicyDocument=json.dumps(permissions_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="ddb-access"))

    api = appsync.create_graphql_api(name=ctx.unique_name("sim2real-appsync-cache-api-"), authenticationType="API_KEY")[
        "graphqlApi"
    ]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    api_key = appsync.create_api_key(apiId=api_id)["apiKey"]["id"]

    sdl = "type Query { increment: Int }\nschema { query: Query }\n"
    _create_schema_and_wait(appsync, api_id, sdl, timeout_s=60)

    ds_name = "counter_ddb"
    _retry_until_ready(
        lambda: appsync.create_data_source(
            apiId=api_id,
            name=ds_name,
            type="AMAZON_DYNAMODB",
            serviceRoleArn=role_arn,
            dynamodbConfig={"tableName": table_name, "awsRegion": ctx.region},
        )
    )

    js_code = (
        "import { util } from '@aws-appsync/utils';\n"
        "export function request(ctx) {\n"
        "  return {\n"
        "    operation: 'UpdateItem',\n"
        "    key: util.dynamodb.toMapValues({ id: 'counter' }),\n"
        "    update: {\n"
        "      expression: 'ADD #v :inc',\n"
        "      expressionNames: { '#v': 'value' },\n"
        "      expressionValues: util.dynamodb.toMapValues({ ':inc': 1 }),\n"
        "    },\n"
        "  };\n"
        "}\n"
        "export function response(ctx) {\n"
        "  return ctx.result.value;\n"
        "}\n"
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="increment",
        dataSourceName=ds_name,
        code=js_code,
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
    )
    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="increment")["resolver"]
    assert resolver["dataSourceName"] == ds_name, (
        f"expected resolver wired to data source {ds_name!r}, got {resolver['dataSourceName']!r}"
    )

    return table_name, role_arn, api, api_key


def _create_schema_and_wait(appsync, api_id: str, sdl: str, timeout_s: float) -> None:
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError("schema creation failed")
        time.sleep(2)
    raise AssertionError(f"schema creation never completed within {timeout_s}s")


def _retry_until_ready(fn, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - IAM role propagation delay
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _wait_cache_status(ctx, appsync, api_id: str, wanted: str, timeout_s: float) -> None:
    start = time.monotonic()
    deadline = start + timeout_s
    while time.monotonic() < deadline:
        status = appsync.get_api_cache(apiId=api_id)["apiCache"]["status"]
        if status == wanted:
            return
        if status == "FAILED":
            raise AssertionError("api cache entered FAILED state")
        time.sleep(2)
    raise AssertionError(
        f"api cache never reached {wanted} within {timeout_s}s (waited {time.monotonic() - start:.0f}s)"
    )


def _graphql_call(ctx, url: str, api_key: str, query: str, timeout_s: float = 15.0) -> dict:
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url,
        data=json.dumps({"query": query}).encode("utf-8"),
        headers={"content-type": "application/json", "x-api-key": api_key, **route_headers},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _wait_post_flush_increment(ctx, url: str, api_key: str, query: str, prior_value: int, timeout_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    last_value = prior_value
    while time.monotonic() < deadline:
        resp = _graphql_call(ctx, url, api_key, query)
        assert "errors" not in resp, resp
        last_value = resp["data"]["increment"]
        if last_value != prior_value:
            return last_value
        time.sleep(3)
    raise AssertionError(f"post-flush query still returned the cached value {last_value} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

