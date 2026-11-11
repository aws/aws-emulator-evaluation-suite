"""appsync-concurrent-conditional-mutations-single-winner."""
from __future__ import annotations

import concurrent.futures
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-concurrent-conditional-mutations-single-winner"
GROUP = 'concurrency'
SERVICES = ['appsync', 'dynamodb']

RACERS = 12

SDL = """schema { query: Query mutation: Mutation }
type Claim {
    id: ID!
    owner: String
}
type Query {
    getClaim(id: ID!): Claim
}
type Mutation {
    claim(id: ID!, owner: String!): Claim
}
"""

JS_CLAIM = """import { util } from '@aws-appsync/utils';
import * as ddb from '@aws-appsync/utils/dynamodb';

export function request(ctx) {
  const { id, owner } = ctx.args;
  return ddb.put({
    key: { id },
    item: { owner },
    condition: { id: { attributeExists: false } },
  });
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
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

    IAM exposes no condition reporting that a trust policy has become effective, so correctness
    comes entirely from the bounded retry at FIRST USE of the permission (the warm-up call at the
    call site) -- not from any wait here.
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


_CONDITION_FAILED = "DynamoDB:ConditionalCheckFailedException"


def _classify(response):
    """('win', body) / ('lose', body) / ('retry', body) for one racer's response.

    A throttle or a still-propagating role is NOT a loser: counting it as one would make the
    invariant measure the wrong thing (11 losers because 3 never reached DynamoDB is not the
    same observation as 11 conditional-check failures).
    """
    status, body = response
    if status != 200 or not isinstance(body, dict):
        return "retry", body
    errors = body.get("errors") or []
    if not errors:
        claim = (body.get("data") or {}).get("claim")
        return ("win", body) if claim else ("retry", body)
    types = {e.get("errorType") for e in errors}
    if types == {_CONDITION_FAILED}:
        return "lose", body
    return "retry", body


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Twelve simultaneous conditional GraphQL mutations produce exactly one winner; every loser
    carries ConditionalCheckFailedException and the stored row equals the winner's value."""
    svc = ctx.client("appsync")
    ddb = ctx.client("dynamodb")
    table, table_arn = _create_table(ctx)

    role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                       "Resource": [table_arn, table_arn + "/*"]}],
    })

    api_id, uris, _arn = _graphql_api(ctx, svc, SDL)
    graphql_uri = uris["GRAPHQL"]

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(
        apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB", serviceRoleArn=role_arn,
        dynamodbConfig={"tableName": table, "awsRegion": ctx.region},
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Mutation", fieldName="claim",
        kind="UNIT", dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_CLAIM,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName="claim")
    )
    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync race key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))

    mutation = (
        "mutation Claim($id: ID!, $owner: String!) "
        "{ claim(id: $id, owner: $owner) { id owner } }"
    )

    def _claim(claim_id, owner):
        return _post_json(ctx, graphql_uri, {"x-api-key": api_key},
                          {"query": mutation, "variables": {"id": claim_id, "owner": owner}})

    # Warm the brand-new data-source role on a DIFFERENT key before racing, so an IAM
    # propagation error cannot masquerade as a lost race. This is the bounded retry at first
    # use of the permission, and it doubles as proof the resolver writes at all.
    warm_id = ctx.unique_name("warm-")
    warm_status, warm_body = _poll_until(
        lambda: _claim(warm_id, "warmup"),
        lambda res: _classify(res)[0] == "win",
        timeout_s=150.0, interval_s=5.0,
        description="the conditional DynamoDB resolver to become invocable (IAM propagation)",
    )
    assert warm_status == 200 and warm_body["data"]["claim"]["owner"] == "warmup", (
        f"the uncontended conditional write did not succeed: {warm_status!r} {warm_body!r}"
    )

    contested = ctx.unique_name("contested-")
    owners = [f"owner-{i:02d}-{ctx.unique_name('')}" for i in range(RACERS)]

    def _race(owner):
        for _attempt in range(4):
            verdict, body = _classify(_claim(contested, owner))
            if verdict != "retry":
                return verdict, owner, body
            time.sleep(1.0)
        return "retry", owner, body

    with concurrent.futures.ThreadPoolExecutor(max_workers=RACERS) as pool:
        outcomes = list(pool.map(_race, owners))

    unresolved = [(o, b) for v, o, b in outcomes if v == "retry"]
    assert not unresolved, (
        f"{len(unresolved)} racer(s) never reached a conditional verdict (throttle or IAM), so "
        f"the invariant would be measured over the wrong population: {unresolved!r}"
    )
    winners = [(o, b) for v, o, b in outcomes if v == "win"]
    losers = [(o, b) for v, o, b in outcomes if v == "lose"]

    assert len(winners) == 1, (
        f"expected exactly one winner out of {RACERS} conditional writes to the same key, got "
        f"{len(winners)}: {[o for o, _ in winners]!r}"
    )
    assert len(losers) == RACERS - 1, (
        f"expected {RACERS - 1} losers, got {len(losers)}"
    )
    loser_types = {
        e.get("errorType") for _o, b in losers for e in (b.get("errors") or [])
    }
    assert loser_types == {_CONDITION_FAILED}, (
        f"every loser must carry exactly the DynamoDB conditional-check errorType; got "
        f"{sorted(loser_types)!r}"
    )
    for _o, b in losers:
        assert (b.get("data") or {}).get("claim") is None, (
            f"a losing racer returned data as well as a conflict error: {b!r}"
        )

    winner_owner, winner_body = winners[0]
    item = ddb.get_item(
        TableName=table, Key={"id": {"S": contested}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, (
        f"a racer reported a successful conditional write but DynamoDB holds no item for "
        f"{contested!r}: winner={winner_body!r}"
    )
    assert item["owner"]["S"] in owners, (
        f"the stored owner is not one of the racers: {item!r}"
    )
    assert item["owner"]["S"] == winner_owner, (
        f"the stored owner {item['owner']['S']!r} disagrees with the racer that was told it "
        f"won ({winner_owner!r}) -- the conditional write is not atomic"
    )
    assert winner_body["data"]["claim"]["owner"] == winner_owner, (
        f"the winner's own response does not echo its owner: {winner_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
