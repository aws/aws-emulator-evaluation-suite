"""deep-appsync-2-appsync-authz-caller-credentials-getitem-denied-item-unchanged."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-2-appsync-authz-caller-credentials-getitem-denied-item-unchanged"
GROUP = "authorization-denied"
SERVICES = ["appsync", "cognito-identity", "dynamodb"]

SDL = """schema { query: Query mutation: Mutation }
type Item {
    pk: String!
    name: String
}
type Query {
    item(pk: String!): Item
}
type Mutation {
    rename(pk: String!, name: String!): Item
}
"""

# A data-source error is NOT fatal to a resolver unless the response handler raises it -- so
# every handler here re-raises ctx.error, which is what aborts the pipeline before its write.
JS_GET_ITEM = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return { operation: 'GetItem', key: util.dynamodb.toMapValues({ pk: ctx.args.pk }),
           consistentRead: true };
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  return ctx.result;
}
"""

JS_UPDATE_NAME = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'UpdateItem',
    key: util.dynamodb.toMapValues({ pk: ctx.args.pk }),
    update: {
      expression: 'SET #n = :n',
      expressionNames: { '#n': 'name' },
      expressionValues: util.dynamodb.toMapValues({ ':n': ctx.args.name }),
    },
  };
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  return ctx.result;
}
"""

JS_PIPELINE = """export function request(ctx) {
  return {};
}

export function response(ctx) {
  return ctx.prev.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

ORIGINAL_NAME = "original"
RENAMED_NAME = "renamed-by-permitted-twin"


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(ctx, probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource / Function names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens."""
    return ctx.unique_name(prefix).replace("-", "_")


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _delete_role(ctx, role_name):
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


def _create_identity_pool(ctx):
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=_alnum(ctx, "sim2real_behav_appsync_authz_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={t["Key"]: t["Value"] for t in _tags_kv()},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_role(ctx, principal, action, condition, policy):
    """An IAM role with one inline policy, its teardown registered.

    IAM exposes no signal that a trust policy is effective; the polls at first use make it correct.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-authz-role-")
    statement = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        statement["Condition"] = condition
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return arn


def _create_guest_role(ctx, pool_id, policy):
    """The pool's unauthenticated role, trusted ONLY by that pool's guest identities."""
    arn = _create_role(
        ctx, {"Federated": "cognito-identity.amazonaws.com"}, "sts:AssumeRoleWithWebIdentity",
        {
            "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
            "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
        },
        policy,
    )
    ctx.client("cognito-identity").set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"unauthenticated": arn}
    )
    return arn


def _guest_credentials(ctx, pool_id):
    """Vend a guest identity's own temporary credentials through the enhanced flow."""
    ci = ctx.client("cognito-identity")
    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    vended = _poll_until(
        ctx, lambda: _try(ci.get_credentials_for_identity, IdentityId=identity_id),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=120.0, interval_s=2.0,
        description=f"GetCredentialsForIdentity for pool {pool_id} to accept the new role",
    )
    c = vended["Credentials"]
    return Credentials(c["AccessKeyId"], c["SecretKey"], c["SessionToken"])


def _signed_post(ctx, url, region, creds, payload, timeout_s=40):
    """SigV4-sign (signing name ``appsync``) and POST -> (status, parsed). 4xx is a RESULT."""
    body = json.dumps(payload).encode()
    request = AWSRequest(method="POST", url=url, data=body,
                         headers={"Content-Type": "application/json"})
    SigV4Auth(creds, "appsync", region).add_auth(request)
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, method="POST", headers={**dict(request.headers), **route_headers})
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


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-authz-tbl-")
    arn = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90}
    )
    return name, arn


def _stored_name(ctx, table, pk):
    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True
    ).get("Item") or {}
    return (item.get("name") or {}).get("S")


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, graphql_uri, api_arn)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        ctx, lambda: svc.get_schema_creation_status(apiId=api_id),
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
    return api_id, uri, api["arn"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A useCallerCredentials DynamoDB data source uses the caller's IAM policy: a guest denied
    GetItem gets a DynamoDB error and its GetItem-then-UpdateItem mutation leaves the item
    unchanged, while a twin allowed GetItem reads and renames it."""
    svc = ctx.client("appsync")
    account = ctx.client("sts").get_caller_identity()["Account"]

    table, table_arn = _create_table(ctx)
    pk = ctx.unique_name("item-")
    ctx.client("dynamodb").put_item(
        TableName=table, Item={"pk": {"S": pk}, "name": {"S": ORIGINAL_NAME}}
    )

    api_id, url, api_arn = _graphql_api(ctx, svc, SDL, authenticationType="AWS_IAM")
    assert api_arn.split(":")[4] == account, (
        f"the api ARN {api_arn!r} does not belong to the caller account {account!r}"
    )

    # Without a serviceRoleArn AppSync answers InternalFailure for every caller, so the data source
    # carries a role that denies dynamodb:* and can never be the credential that reads.
    svc_role = _create_role(
        ctx, {"Service": "appsync.amazonaws.com"}, "sts:AssumeRole", None,
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": ["dynamodb:*"], "Resource": ["*"]},
        ]},
    )
    ds_name = _alnum(ctx, "ddb")
    svc.create_data_source(
        apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB", serviceRoleArn=svc_role,
        dynamodbConfig={"tableName": table, "awsRegion": ctx.region, "useCallerCredentials": True},
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    stored = svc.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert (stored.get("dynamodbConfig") or {}).get("useCallerCredentials") is True, (
        f"the data source did not retain useCallerCredentials=true: {stored!r}"
    )
    assert stored.get("serviceRoleArn") == svc_role, (
        f"the data source must carry the deny-all service role: {stored.get('serviceRoleArn')!r}"
    )

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="item", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_GET_ITEM,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="item"))
    fn_ids = []
    for label, code in (("read", JS_GET_ITEM), ("write", JS_UPDATE_NAME)):
        fn_id = svc.create_function(
            apiId=api_id, name=_alnum(ctx, label), dataSourceName=ds_name,
            runtime=APPSYNC_JS, code=code,
        )["functionConfiguration"]["functionId"]
        ctx.on_cleanup(lambda f=fn_id: svc.delete_function(apiId=api_id, functionId=f))
        fn_ids.append(fn_id)
    svc.create_resolver(
        apiId=api_id, typeName="Mutation", fieldName="rename", kind="PIPELINE",
        pipelineConfig={"functions": fn_ids}, runtime=APPSYNC_JS, code=JS_PIPELINE,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName="rename")
    )

    graphql_allow = {"Effect": "Allow", "Action": ["appsync:GraphQL"],
                     "Resource": [f"{api_arn}/*"]}
    permitted_pool = _create_identity_pool(ctx)
    _create_guest_role(ctx, permitted_pool, {"Version": "2012-10-17", "Statement": [
        graphql_allow,
        {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem"],
         "Resource": [table_arn]},
    ]})
    denied_pool = _create_identity_pool(ctx)
    _create_guest_role(ctx, denied_pool, {"Version": "2012-10-17", "Statement": [
        graphql_allow,
        {"Effect": "Allow", "Action": ["dynamodb:UpdateItem"], "Resource": [table_arn]},
        {"Effect": "Deny", "Action": ["dynamodb:GetItem"], "Resource": [table_arn]},
    ]})
    permitted = _guest_credentials(ctx, permitted_pool)
    denied = _guest_credentials(ctx, denied_pool)

    query = {"query": "query Q($pk: String!) { item(pk: $pk) { pk name } }",
             "variables": {"pk": pk}}

    # ---- POSITIVE CONTROL: the permitted twin reads (also the IAM-propagation barrier) -------
    _status, ok = _poll_until(
        ctx, lambda: _signed_post(ctx, url, ctx.region, permitted, query),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=240.0, interval_s=2.0,
        description="the permitted twin's GetItem through useCallerCredentials to succeed",
    )
    assert ok == {"data": {"item": {"pk": pk, "name": ORIGINAL_NAME}}}, (
        f"the permitted twin must read the seeded item through its own credentials, got {ok!r}"
    )

    # ---- DENIED query: AppSync admits the request, DynamoDB refuses the caller --------------
    # The poll only waits out the denied role's appsync:GraphQL propagation (a 401 before the
    # resolver ever runs); it accepts the first response that reached the resolver.
    status, body = _poll_until(
        ctx, lambda: _signed_post(ctx, url, ctx.region, denied, query),
        lambda res: res[0] == 200,
        timeout_s=240.0, interval_s=2.0,
        description="the denied twin's request to be admitted by AppSync and reach the resolver",
    )
    assert body.get("data") == {"item": None}, (
        f"the denied twin's GetItem must yield a null item, got {body!r}"
    )
    errors = body.get("errors") or []
    assert len(errors) == 1, f"the denied query must carry exactly one error, got {errors!r}"
    denied_type = errors[0].get("errorType")
    assert denied_type == "DynamoDB:DynamoDbException", (
        f"the caller-credential denial must surface as the DynamoDB error class, got "
        f"{denied_type!r} in {errors[0]!r}"
    )
    # message varies: AWS appends the DynamoDB request id and the SDK attempt count to it
    assert "dynamodb:GetItem" in (errors[0].get("message") or ""), (
        f"the denial must name the refused action dynamodb:GetItem: {errors[0].get('message')!r}"
    )
    assert errors[0].get("path") == ["item"], f"error path: {errors[0].get('path')!r}"

    # ---- DENIED mutation: the pipeline aborts on the read, the write never lands ------------
    mutation = {
        "query": "mutation M($pk: String!, $n: String!) { rename(pk: $pk, name: $n) { pk name } }",
        "variables": {"pk": pk, "n": "renamed-by-denied-twin"},
    }
    m_status, m_body = _signed_post(ctx, url, ctx.region, denied, mutation)
    assert m_status == 200 and m_body.get("data") == {"rename": None}, (
        f"the denied twin's mutation must resolve to null, got {m_status!r} {m_body!r}"
    )
    m_errors = m_body.get("errors") or []
    # message varies: AWS appends the DynamoDB request id and the SDK attempt count to it
    assert len(m_errors) == 1 and m_errors[0].get("errorType") == "DynamoDB:DynamoDbException", (
        f"the denied mutation must fail on the caller-credential GetItem, got {m_errors!r}"
    )
    after_denied = _stored_name(ctx, table, pk)
    assert after_denied == ORIGINAL_NAME, (
        f"the item must be UNCHANGED after the denied twin's mutation, name is {after_denied!r}"
    )

    # ---- REPAIR: the permitted twin's mutation writes -----------------------------------------
    mutation["variables"]["n"] = RENAMED_NAME
    r_status, r_body = _signed_post(ctx, url, ctx.region, permitted, mutation)
    assert r_status == 200 and r_body == {"data": {"rename": {"pk": pk, "name": RENAMED_NAME}}}, (
        f"the permitted twin's mutation must rename the item, got {r_status!r} {r_body!r}"
    )
    after_permitted = _stored_name(ctx, table, pk)
    assert after_permitted == RENAMED_NAME, (
        f"the table must read back the permitted twin's write, name is {after_permitted!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
