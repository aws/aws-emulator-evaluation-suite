"""deep-appsync-2-appsync-authz-ttl-override-zero-reinvokes-authorizer-every-request."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-2-appsync-authz-ttl-override-zero-reinvokes-authorizer-every-request"
GROUP = "authorization-cache"
SERVICES = ["appsync", "dynamodb", "lambda"]

API_TTL_S = 300
REQUESTS_PER_LEG = 4

SDL = """schema { query: Query }
type Query {
    whoami: String
}
"""

# Every invocation increments an atomic counter in DynamoDB keyed by the token BEFORE answering,
# so "how many times did AppSync call the authorizer for this token" is answered on a store
# AppSync never touches. ``ttlOverride: 0`` is returned only for ``nocache-`` tokens.
AUTHORIZER_SRC = '''import os

import boto3

_ddb = boto3.client("dynamodb")


def handler(event, context):
    token = (event or {}).get("authorizationToken") or ""
    _ddb.update_item(
        TableName=os.environ["SIM2REAL_TABLE"],
        Key={"pk": {"S": token}},
        UpdateExpression="ADD invocations :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    )
    answer = {"isAuthorized": True, "resolverContext": {"token": token}}
    if token.startswith("nocache-"):
        answer["ttlOverride"] = 0
    return answer
'''

JS_ECHO_IDENTITY = """import { runtime } from '@aws-appsync/utils';

export function request(ctx) {
  runtime.earlyReturn(ctx.identity.resolverContext.token);
  return {};
}

export function response(ctx) {
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(ctx, probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; raise on timeout."""
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
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=40):
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


def _zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", source)
    return buf.getvalue()


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _delete_role(ctx, role_name):
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


def _create_lambda_role(ctx, inline_policy):
    """An execution role for the authorizer, with its teardown registered."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-authz-role-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return arn


def _delete_log_group_when_it_exists(ctx, group, timeout_s=150.0, quiet_s=30.0):
    """Delete a service-created log group until it stays gone for ``quiet_s``.

    A buffered stream can flush after the function is deleted and recreate the group.
    """
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_delete = None
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
            last_delete = time.monotonic()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group} not deleted: {code}") from exc
            if last_delete is not None and time.monotonic() - last_delete >= quiet_s:
                return
        if time.monotonic() >= deadline:
            if last_delete is None:
                raise RuntimeError(
                    f"log group {group} never materialised within {timeout_s}s"
                )
            elif time.monotonic() - last_delete < quiet_s:
                raise RuntimeError(f"log group {group} kept reappearing for {timeout_s}s")
            return
        time.sleep(3.0)


def _create_function(ctx, source, role_arn, env):
    """A python Lambda, its teardown, its log group's teardown, and a wait for Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-appsync-authz-fn-")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _delete_log_group_when_it_exists(ctx, f"/aws/lambda/{name}"))
    created = _poll_until(
        ctx, lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=20, Publish=False,
            Environment={"Variables": env},
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=2.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") in ("Active", "Failed"),
        timeout_s=180.0, interval_s=2.0,
        description=f"Lambda {name} reaching a terminal State",
    )
    assert cfg["State"] == "Active", (
        f"the authorizer function did not become Active: {cfg.get('State')!r} "
        f"{cfg.get('StateReason')!r}"
    )
    return name, created["FunctionArn"]


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-authz-ctr-")
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


def _count(ctx, table, token):
    """The authorizer's invocation count for ``token``, read strongly consistent."""
    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"pk": {"S": token}}, ConsistentRead=True
    ).get("Item")
    return int(item["invocations"]["N"]) if item else 0


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With a 300s authorizer TTL, a token whose answer carries ttlOverride=0 invokes the authorizer
    on every request, while a token without it is invoked once and stays cached afterwards.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
    """
    svc = ctx.client("appsync")
    lam = ctx.client("lambda")

    table, table_arn = _create_table(ctx)
    exec_role = _create_lambda_role(ctx, {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
                       "Resource": [table_arn]}],
    })
    fn_name, fn_arn = _create_function(ctx, AUTHORIZER_SRC, exec_role, {"SIM2REAL_TABLE": table})

    api_id, url, api_arn = _graphql_api(
        ctx, svc, SDL,
        authenticationType="AWS_LAMBDA",
        lambdaAuthorizerConfig={
            "authorizerUri": fn_arn, "authorizerResultTtlInSeconds": API_TTL_S,
        },
    )
    stored = svc.get_graphql_api(apiId=api_id)["graphqlApi"].get("lambdaAuthorizerConfig") or {}
    assert stored.get("authorizerResultTtlInSeconds") == API_TTL_S, (
        f"the api did not retain the authorizer TTL under test: expected {API_TTL_S}, got "
        f"{stored.get('authorizerResultTtlInSeconds')!r}"
    )

    lam.add_permission(
        FunctionName=fn_name, StatementId="sim2real-appsync-authorizer",
        Action="lambda:InvokeFunction", Principal="appsync.amazonaws.com", SourceArn=api_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(
        FunctionName=fn_name, StatementId="sim2real-appsync-authorizer"
    ))

    ds_name = _alnum(ctx, "none")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="whoami", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO_IDENTITY,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="whoami"))

    document = {"query": "query Who { whoami }"}

    def _ask(token):
        return _post_json(ctx, url, {"Authorization": token}, document)

    # ---- barrier: an authorized request, and the side-channel recorded it -------------------
    # AppSync answers 401 while the lambda:InvokeFunction permission is still propagating.
    warm_token = ctx.unique_name("warm-")
    _poll_until(
        ctx, lambda: _ask(warm_token),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=300.0, interval_s=2.0,
        description="the Lambda authorizer to become invocable and authorize a request",
    )
    warm_count = _count(ctx, table, warm_token)
    assert warm_count >= 1, (
        f"the warm-up request was authorized but the DynamoDB counter for its token reads "
        f"{warm_count!r}; the side-channel records nothing, so no count below would mean anything"
    )

    def _leg(token):
        for i in range(REQUESTS_PER_LEG):
            status, body = _ask(token)
            assert status == 200 and body == {"data": {"whoami": token}}, (
                f"request {i + 1}/{REQUESTS_PER_LEG} for {token!r} must be authorized and carry "
                f"its resolverContext, got {status!r} {body!r}"
            )
        return _count(ctx, table, token)

    # ---- CONTROL: no override -> the api's 300s TTL caches after one invocation -------------
    cached_token = ctx.unique_name("cache-")
    cached_count = _leg(cached_token)
    assert cached_count == 1, (
        f"with authorizerResultTtlInSeconds={API_TTL_S} and no ttlOverride, {REQUESTS_PER_LEG} "
        f"identical requests must invoke the authorizer exactly once, counter reads "
        f"{cached_count!r}"
    )

    # ---- OVERRIDE: ttlOverride=0 -> invoked on every single request -------------------------
    nocache_token = ctx.unique_name("nocache-")
    nocache_count = _leg(nocache_token)
    assert nocache_count == REQUESTS_PER_LEG, (
        f"an authorizer answer with ttlOverride=0 must not be cached: {REQUESTS_PER_LEG} requests "
        f"must invoke the authorizer {REQUESTS_PER_LEG} times, counter reads {nocache_count!r}"
    )

    # ---- the control token is STILL cached after the override leg --------------------------
    # ttlOverride is per-answer: the nocache answers must not have evicted or disabled the
    # api-wide cache for other tokens.
    final_cached = _leg(cached_token)
    assert final_cached == 1, (
        f"after the ttlOverride=0 leg, {REQUESTS_PER_LEG} more requests with the no-override "
        f"token must still be served from cache, counter moved to {final_cached!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
