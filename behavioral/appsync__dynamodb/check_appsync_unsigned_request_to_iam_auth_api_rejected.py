"""appsync-unsigned-request-to-iam-auth-api-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-unsigned-request-to-iam-auth-api-rejected"
GROUP = 'overly-permissive'
SERVICES = ['appsync', 'dynamodb']

SDL = """schema { query: Query mutation: Mutation }
type Mark {
    id: ID!
    stamp: String
}
type Query {
    getMark(id: ID!): Mark
}
type Mutation {
    mark(id: ID!, stamp: String!): Mark
}
"""

JS_MARK = """import { util } from '@aws-appsync/utils';
import * as ddb from '@aws-appsync/utils/dynamodb';

export function request(ctx) {
  const { id, stamp } = ctx.args;
  return ddb.put({ key: { id }, item: { stamp } });
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


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False, so a poll timeout names
    the code that kept it from settling."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


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

    The short sleep is the ONE sanctioned bare wait: IAM exposes no condition reporting that a
    trust policy has become effective. It only makes the bounded retry at FIRST USE of the
    permission cheaper -- that retry, not this sleep, is what makes the check correct.
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


def _sigv4_headers(ctx, url, body):
    """SigV4-sign a raw HTTPS POST for the ``appsync`` signing name.

    The credentials come from ``ctx.subprocess_env()`` -- the one PUBLIC seam that exposes the
    LEASED keys -- never from the ambient chain, which is a management-account principal. If the
    signature were built from the wrong identity the CONTROL leg would fail, which is the correct
    failure mode: the check fails rather than silently asserting nothing.
    """
    env = ctx.subprocess_env()
    akid = env.get("AWS_ACCESS_KEY_ID")
    assert akid, (
        "no signing credentials are reachable through ctx.subprocess_env(); the signed control "
        "leg cannot be built, and falling back to the ambient chain would sign as a DIFFERENT "
        "account"
    )
    creds = Credentials(akid, env["AWS_SECRET_ACCESS_KEY"], env.get("AWS_SESSION_TOKEN"))
    request = AWSRequest(
        method="POST", url=url, data=body,
        headers={"Content-Type": "application/json"},
    )
    SigV4Auth(creds, "appsync", ctx.region).add_auth(request)
    return dict(request.headers)


def _post_raw(ctx, url, headers, body, timeout_s=30):
    """POST an already-serialised body -> (status, parsed). The body must be byte-identical to
    the one that was signed, so this takes bytes rather than re-serialising a dict."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, method="POST", headers={**headers, **route_headers})
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An unsigned POST to an AWS_IAM API gets 401 with one UnauthorizedException and its resolver
    writes nothing, while the identical SigV4-signed request writes the row."""
    svc = ctx.client("appsync")
    ddb = ctx.client("dynamodb")
    table, table_arn = _create_table(ctx)

    role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                       "Resource": [table_arn, table_arn + "/*"]}],
    })

    api_id, uris, _arn = _graphql_api(ctx, svc, SDL, authenticationType="AWS_IAM")
    graphql_uri = uris["GRAPHQL"]

    ds_name = _alnum(ctx, "ds")
    _poll_until(
        lambda: _try(svc.create_data_source, apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB",
                     serviceRoleArn=role_arn,
                     dynamodbConfig={"tableName": table, "awsRegion": ctx.region}),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description="CreateDataSource to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Mutation", fieldName="mark",
        kind="UNIT", dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_MARK,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName="mark")
    )

    mutation = ("mutation Mark($id: ID!, $stamp: String!) "
                "{ mark(id: $id, stamp: $stamp) { id stamp } }")
    denied_marker = ctx.unique_name("denied-")
    control_marker = ctx.unique_name("control-")

    def _body(marker):
        return json.dumps(
            {"query": mutation, "variables": {"id": marker, "stamp": marker}}
        ).encode()

    # ---- break exactly one thing: send NO Authorization header ----
    unsigned_status, unsigned_body = _post_raw(
        ctx, graphql_uri, {"Content-Type": "application/json"}, _body(denied_marker)
    )
    assert unsigned_status == 401, (
        f"an unsigned request to an AWS_IAM API must be refused at the transport; got "
        f"{unsigned_status!r} body={unsigned_body!r}"
    )
    errors = unsigned_body.get("errors") or []
    assert len(errors) == 1, f"expected exactly one error on the refusal, got {errors!r}"
    assert errors[0].get("errorType") == "UnauthorizedException", (
        f"the unsigned request was refused with the wrong errorType: {errors[0]!r}"
    )
    assert "data" not in unsigned_body, (
        f"a transport-level refusal must not carry a GraphQL data envelope: {unsigned_body!r}"
    )

    # ---- the effect is absent: the resolver never reached DynamoDB ----
    denied_read = ddb.get_item(
        TableName=table, Key={"id": {"S": denied_marker}}, ConsistentRead=True
    )
    assert "Item" not in denied_read, (
        f"the resolver RAN despite the request being unauthorized -- the unsigned mutation's "
        f"item is in the table: {denied_read.get('Item')!r}"
    )

    # ---- positive control: the identical request, signed ----
    control_body = _body(control_marker)
    signed_status, signed_body = _poll_until(
        lambda: _post_raw(
            ctx, graphql_uri, _sigv4_headers(ctx, graphql_uri, control_body), control_body
        ),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=150.0, interval_s=5.0,
        description="the signed control request to resolve (IAM propagation on the new role)",
    )
    assert signed_status == 200, (
        f"the signed control leg did not return 200: {signed_status!r} {signed_body!r}"
    )
    assert signed_body["data"]["mark"]["id"] == control_marker, (
        f"the signed control leg did not resolve the mutation: {signed_body!r}"
    )

    control_read = ddb.get_item(
        TableName=table, Key={"id": {"S": control_marker}}, ConsistentRead=True
    )
    assert control_read.get("Item", {}).get("stamp", {}).get("S") == control_marker, (
        f"the signed control did not write its item, so the effect-absent assertion above "
        f"cannot be attributed to the missing signature: {control_read!r}"
    )

    # Re-read the denied marker AFTER the control has landed: the signed request is the barrier
    # that proves a write through this resolver is visible by now, so the denied marker's
    # continued absence is not simply a read that was too early.
    denied_after = ddb.get_item(
        TableName=table, Key={"id": {"S": denied_marker}}, ConsistentRead=True
    )
    assert "Item" not in denied_after, (
        f"the unsigned mutation's item appeared later; the refusal did not prevent the write: "
        f"{denied_after.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
