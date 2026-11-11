"""appsync-unit-resolver-reads-dynamodb-via-api-key."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-unit-resolver-reads-dynamodb-via-api-key"

GROUP = "graphql"

SERVICES = ["appsync", "dynamodb"]


_SCHEMA = """
type Widget {
  id: ID!
  name: String
  count: Int
}

type Query {
  getWidget(id: ID!): Widget
}

schema {
  query: Query
}
"""

_REQUEST_TEMPLATE = """{
  "version": "2018-05-29",
  "operation": "GetItem",
  "key": {
    "id": $util.dynamodb.toDynamoDBJson($ctx.args.id)
  }
}"""

_RESPONSE_TEMPLATE = "$util.toJson($ctx.result)"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AppSync VTL UNIT resolver on an AMAZON_DYNAMODB data source, queried with an API key,
    returns an item seeded directly via DynamoDB, with its numeric attribute as a GraphQL Int
    rather than a DynamoDB {"N": ...} map.
    """
    table = _create_ddb_table(ctx, kind="widgets", key="id")
    widget_id = ctx.unique_name("widget-")
    widget_name = ctx.unique_name("name-")
    ctx.client("dynamodb").put_item(
        TableName=table["name"],
        Item={
            "id": {"S": widget_id},
            "name": {"S": widget_name},
            "count": {"N": "7"},
        },
    )
    assert _ddb_item(ctx, table["name"], widget_id, key="id") is not None, (
        "precondition: the seed item should be readable directly from DynamoDB"
    )

    role = _create_role(
        ctx,
        "appsync.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["dynamodb:GetItem"],
                    "Resource": table["arn"],
                }
            ],
        },
    )

    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=_xname(ctx, "gqlapi"),
        authenticationType="API_KEY",
        tags=_xsvc_resource_tags(),
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: ctx.client("appsync").delete_graphql_api(apiId=api_id))

    appsync.start_schema_creation(apiId=api_id, definition=_SCHEMA.encode())
    status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id),
        lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=120.0,
        interval_s=3.0,
        description="AppSync schema creation reaching a terminal status",
    )
    assert status.get("status") in ("SUCCESS", "ACTIVE"), (
        f"schema creation failed: {status!r}"
    )

    # AppSync data-source names must match ^[_A-Za-z][_0-9A-Za-z]*$.
    data_source = "ds_" + re.sub(r"[^0-9A-Za-z_]", "_", _xname(ctx, "ddbsource"))
    appsync.create_data_source(
        apiId=api_id,
        name=data_source,
        type="AMAZON_DYNAMODB",
        serviceRoleArn=role["arn"],
        dynamodbConfig={"tableName": table["name"], "awsRegion": ctx.region},
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        dataSourceName=data_source,
        kind="UNIT",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_RESPONSE_TEMPLATE,
    )
    api_key = appsync.create_api_key(
        apiId=api_id, description="sim2real-xsvc appsync ddb resolver check"
    )["apiKey"]["id"]

    # Use the API's own GRAPHQL URI rather than constructing an appsync-api.<region> host.
    endpoint = _poll_until(
        lambda: (
            ctx.client("appsync")
            .get_graphql_api(apiId=api_id)["graphqlApi"]
            .get("uris", {})
            .get("GRAPHQL")
        ),
        lambda u: bool(u),
        timeout_s=60.0,
        interval_s=3.0,
        description="the API's GRAPHQL endpoint URI",
    )

    query = (
        "query GetWidget($id: ID!) { getWidget(id: $id) { id name count } }"
    )
    body = json.dumps({"query": query, "variables": {"id": widget_id}}).encode()
    headers = {"Content-Type": "application/json", "x-api-key": api_key}

    def _resolved(status, _headers, text):
        """True only once the resolver returned the item.

        AppSync answers 200 with an `errors` array ("Unable to assume role") while the new
        data-source role propagates, so status alone cannot end the poll.
        """
        if status != 200:
            return False
        try:
            payload = json.loads(text)
        except ValueError:
            return False
        return not payload.get("errors") and (payload.get("data") or {}).get("getWidget")

    status_code, _, text = _poll_http(
        ctx, endpoint,
        accept=_resolved,
        method="POST",
        body=body,
        headers=headers,
        timeout_s=180.0,
        description="AppSync GraphQL query",
    )
    assert status_code == 200, (
        f"expected 200 from the GraphQL endpoint, got {status_code}: {text!r}"
    )
    payload = json.loads(text)
    assert not payload.get("errors"), (
        f"the resolver returned GraphQL errors instead of the item: {payload.get('errors')!r} "
        f"(an 'Unable to assume role' error here is IAM propagation; a mapping-template "
        f"error means $util.dynamodb.toDynamoDBJson was not evaluated)"
    )
    widget = (payload.get("data") or {}).get("getWidget")
    assert widget is not None, (
        f"getWidget resolved to null — the UNIT resolver did not reach DynamoDB: {payload!r}"
    )
    assert widget.get("id") == widget_id, (
        f"expected id {widget_id!r}, got {widget.get('id')!r}"
    )
    assert widget.get("name") == widget_name, (
        f"expected name {widget_name!r}, got {widget.get('name')!r} (a null here means the "
        f"GetItem returned nothing and the response template mapped an empty result)"
    )
    assert widget.get("count") == 7, (
        f"expected count to arrive as the GraphQL Int 7, got {widget.get('count')!r} "
        f"(a dict like {{'N': '7'}} means the DynamoDB attribute-value form leaked through "
        f"the response mapping template unconverted)"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _stays_absent(
    probe, predicate, *, window_s=25.0, interval_s=2.5, description="effect"
):
    """Assert predicate(probe()) stays falsy for a whole bounded settle window."""
    deadline = time.monotonic() + window_s
    while True:
        last = probe()
        assert not predicate(last), (
            f"{description} appeared but must NOT have (delivery was suppressed "
            f"upstream). Observed: {last!r}"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _http(ctx, method, url, body=None, headers=None, timeout_s=20):
    """HTTP request via urllib. Returns (status, lower-cased headers, text).

    A 4xx/5xx is returned as a result rather than raised.
    """
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, method=method, headers={**(headers or {}), **route_headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as e:
        return (
            e.code,
            {k.lower(): v for k, v in e.headers.items()},
            e.read().decode("utf-8", "replace"),
        )


def _poll_http(
    ctx, url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=3.0,
    description="invoke URL",
):
    """Poll a URL until accept(status, headers, text) is true; return (status, headers, text).

    Connection-level errors while DNS/TLS settles are retried, not raised.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(ctx, method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 - execute-api DNS/TLS settling
            last = (None, {}, "connection error")
        else:
            if accept(*last):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} {url} never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:400]!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=None):
    """Create an IAM role and register its (policies-first) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_ddb_table(ctx, kind="table", key="pk"):
    """Create an on-demand DynamoDB table with a single STRING hash key. Returns {name,arn}."""
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, kind)
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=90.0,
        interval_s=2.0,
        description=f"DynamoDB table {name} ACTIVE",
    )
    return {"name": name, "arn": resp["TableDescription"]["TableArn"], "key": key}


def _ddb_item(ctx, table, key_value, key="pk"):
    """GetItem (consistent read) or None."""
    got = ctx.client("dynamodb").get_item(
        TableName=table, Key={key: {"S": key_value}}, ConsistentRead=True
    )
    return got.get("Item")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
