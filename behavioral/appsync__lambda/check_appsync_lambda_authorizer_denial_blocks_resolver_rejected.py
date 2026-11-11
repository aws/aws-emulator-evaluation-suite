"""appsync-lambda-authorizer-denial-blocks-resolver-rejected."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-lambda-authorizer-denial-blocks-resolver-rejected"
GROUP = 'overly-permissive'
SERVICES = ['appsync', 'lambda']

GOOD_TOKEN = "sim2real-good"
BAD_TOKEN = "sim2real-bad"
TENANT = "acme"
RESOLVER_LOG_PREFIX = "RESOLVER-RAN"

SDL = """schema { query: Query }
type Identity {
    tenant: String
    marker: String
}
type Query {
    whoami(marker: String!): Identity
}
"""

AUTHORIZER_SRC = f'''def handler(event, context):
    token = (event or {{}}).get("authorizationToken")
    return {{
        "isAuthorized": token == {GOOD_TOKEN!r},
        "resolverContext": {{"tenant": {TENANT!r}}},
    }}
'''

RESOLVER_SRC = f'''def handler(event, context):
    args = (event or {{}}).get("arguments") or {{}}
    marker = args.get("marker") or ""
    identity = (event or {{}}).get("identity") or {{}}
    tenant = (identity.get("resolverContext") or {{}}).get("tenant")
    # The ONLY durable trace that this resolver ran for a given marker.
    print({RESOLVER_LOG_PREFIX!r} + " " + marker)
    return {{"tenant": tenant, "marker": marker}}
'''

JS_INVOKE = """export function request(ctx) {
  return {
    operation: 'Invoke',
    payload: { arguments: ctx.args, identity: ctx.identity },
  };
}

export function response(ctx) {
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


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


def _post_json(ctx, url, headers, payload, timeout_s=40):
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


def _zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", source)
    return buf.getvalue()


def _delete_role(ctx, role_name):
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


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=()):
    """Create an IAM role trusted by ``trust_service`` and register its teardown.

    IAM exposes no condition reporting that a trust policy has become effective, so this returns
    the ARN immediately. Every caller must treat its first use of the role as retryable: the
    bounded retry there -- not a wait here -- is what makes the check correct.
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
    for arn in managed_policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                            PolicyDocument=json.dumps(inline_policy))
    return resp["Role"]["Arn"]


def _create_function(ctx, source, role_arn):
    """Create a python Lambda, register its teardown and that of the log group Lambda creates on
    first invocation (the teardown waits for that group to exist), and wait for Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-appsync-fn-")
    created = _poll_until(
        lambda: _try_create_function(lam, name, source, role_arn),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=120.0, interval_s=5.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    ctx.on_cleanup(lambda: _delete_log_group_when_it_exists(ctx, name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s in ("Active", "Failed"),
        timeout_s=120.0, interval_s=3.0,
        description=f"Lambda {name} reaching a terminal State",
    )
    state = lam.get_function_configuration(FunctionName=name)
    assert state["State"] == "Active", f"the function did not become Active: {state!r}"
    return name, created["FunctionArn"]


def _try_create_function(lam, name, source, role_arn):
    """The created config, or the AWS error code -- never a bare False, so a poll timeout names
    the code that kept it from settling."""
    try:
        return lam.create_function(
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=15, Publish=False, Tags=dict(
                (t["Key"], t["Value"]) for t in _tags_kv()
            ),
        )
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _delete_log_group_when_it_exists(ctx, function_name, timeout_s=300.0):
    """Delete /aws/lambda/<fn>, waiting up to timeout_s for Lambda to create it on first invocation;
    raise on any other error or if it never appears."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group} not deleted: {code}") from exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"log group {group} never materialised within {timeout_s}s"
                ) from exc
            time.sleep(2.0)


def _log_messages(ctx, function_name, needle):
    """Every log message in the function's group containing ``needle``. Paginated, and an
    absent group means no events rather than an error."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    out = []
    try:
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(logGroupName=group, filterPattern=f'"{needle}"'):
            out.extend(e.get("message", "") for e in page.get("events", []))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return []
        raise
    return out


def _try_create_data_source(svc, api_id, ds_name, role_arn, resolver_arn):
    """The created data source, or the AWS error code -- never a bare False, so a poll timeout
    names the code that kept the brand-new service role from being accepted."""
    try:
        return svc.create_data_source(
            apiId=api_id, name=ds_name, type="AWS_LAMBDA", serviceRoleArn=role_arn,
            lambdaConfig={"lambdaFunctionArn": resolver_arn},
        )
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, uris, arn)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
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
    assert status["status"] in ("SUCCESS", "ACTIVE"), f"schema creation failed: {status!r}"
    uris = api.get("uris") or {}
    assert uris.get("GRAPHQL"), f"the API exposed no GRAPHQL endpoint URI: {uris!r}"
    return api_id, uris, api["arn"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A Lambda authorizer answering isAuthorized=false yields 401 UnauthorizedException and the
    resolver never runs, while an authorized request reaches the resolver with the authorizer's
    resolverContext in ctx.identity."""
    svc = ctx.client("appsync")
    lam = ctx.client("lambda")

    exec_role = _create_role(
        ctx, "lambda.amazonaws.com",
        managed_policies=("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",),
    )
    authorizer_name, authorizer_arn = _create_function(ctx, AUTHORIZER_SRC, exec_role)
    resolver_name, resolver_arn = _create_function(ctx, RESOLVER_SRC, exec_role)

    api_id, uris, api_arn = _graphql_api(
        ctx, svc, SDL,
        authenticationType="AWS_LAMBDA",
        lambdaAuthorizerConfig={
            "authorizerUri": authorizer_arn,
            # No result caching, so the deny and allow legs each invoke the authorizer.
            "authorizerResultTtlInSeconds": 0,
        },
    )
    graphql_uri = uris["GRAPHQL"]

    lam.add_permission(
        FunctionName=authorizer_name, StatementId="sim2real-appsync-authorizer",
        Action="lambda:InvokeFunction", Principal="appsync.amazonaws.com", SourceArn=api_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=authorizer_name, StatementId="sim2real-appsync-authorizer"
        )
    )

    ds_role = _create_role(ctx, "appsync.amazonaws.com", inline_policy={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["lambda:InvokeFunction"],
                       "Resource": [resolver_arn, resolver_arn + ":*"]}],
    })
    ds_name = _alnum(ctx, "ds")
    _poll_until(
        lambda: _try_create_data_source(svc, api_id, ds_name, ds_role, resolver_arn),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=120.0, interval_s=5.0,
        description=f"CreateDataSource {ds_name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="whoami",
        kind="UNIT", dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_INVOKE,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="whoami")
    )

    query = "query Who($marker: String!) { whoami(marker: $marker) { tenant marker } }"
    warm_marker = ctx.unique_name("warmmark-")
    denied_marker = ctx.unique_name("deniedmark-")
    allowed_marker = ctx.unique_name("allowedmark-")

    def _ask(token, marker):
        return _post_json(ctx, graphql_uri, {"Authorization": token},
                          {"query": query, "variables": {"marker": marker}})

    # ---- barrier FIRST: prove the authorizer is invocable, on the ACCEPTED token ----
    # While lambda:InvokeFunction for appsync.amazonaws.com propagates, AppSync also answers 401,
    # so only a successful authorized request proves the authorizer is reachable.
    #
    # While the data source role is still propagating, AppSync answers 200 with a null
    # `whoami` and no errors, so the warm-up waits for a non-null `whoami`.
    warm_status, warm_body = _poll_until(
        lambda: _ask(GOOD_TOKEN, warm_marker),
        lambda res: (
            res[0] == 200 and not (res[1] or {}).get("errors")
            and ((res[1] or {}).get("data") or {}).get("whoami") is not None
        ),
        timeout_s=180.0, interval_s=5.0,
        description="the Lambda authorizer to become invocable and the resolver invoke to stop returning null",
    )
    assert (warm_body["data"]["whoami"] or {}).get("tenant") == TENANT, (
        f"the authorizer is reachable but did not authorize the good token: {warm_status!r} "
        f"{warm_body!r}"
    )

    # ---- break exactly one thing: a token the authorizer refuses ----
    denied_status, denied_body = _ask(BAD_TOKEN, denied_marker)
    assert denied_status == 401, (
        f"an authorizer returning isAuthorized=false must refuse at the transport; got "
        f"{denied_status!r} {denied_body!r}"
    )
    denied_errors = denied_body.get("errors") or []
    assert len(denied_errors) == 1, (
        f"expected exactly one error on the denial, got {denied_errors!r}"
    )
    assert denied_errors[0].get("errorType") == "UnauthorizedException", (
        f"the denial carried the wrong errorType: {denied_errors[0]!r}"
    )
    assert "data" not in denied_body, (
        f"the refused request still returned a GraphQL data envelope: {denied_body!r}"
    )

    # ---- positive control: identical request, the token the authorizer accepts, issued AFTER
    # the denial so its log line is a valid barrier for the denial's absence ----
    allowed_status, allowed_body = _ask(GOOD_TOKEN, allowed_marker)
    assert allowed_status == 200, (
        f"the authorized control leg did not return 200: {allowed_status!r} {allowed_body!r}"
    )
    assert not allowed_body.get("errors"), (
        f"the authorized control leg returned errors: {allowed_body['errors']!r}"
    )
    who = allowed_body["data"]["whoami"]
    assert who["tenant"] == TENANT, (
        f"the authorizer's resolverContext did not reach ctx.identity inside the resolver; "
        f"expected tenant {TENANT!r}, got {who!r}"
    )
    assert who["marker"] == allowed_marker, (
        f"the resolver did not echo the authorized marker: {who!r}"
    )

    # ---- the barrier: the authorized invocation's log line has been delivered ----
    _poll_until(
        lambda: _log_messages(ctx, resolver_name, RESOLVER_LOG_PREFIX),
        lambda msgs: any(allowed_marker in m for m in msgs),
        timeout_s=150.0, interval_s=5.0,
        description="the AUTHORIZED invocation's resolver log line to be delivered",
    )

    # ---- and the effect is absent: the denied request never reached the resolver ----
    ran_for = _log_messages(ctx, resolver_name, RESOLVER_LOG_PREFIX)
    assert any(allowed_marker in m for m in ran_for), (
        f"the barrier passed but the authorized marker is gone from the log: {ran_for!r}"
    )
    assert not any(denied_marker in m for m in ran_for), (
        f"the resolver RAN for the request the authorizer refused -- its log line is present, "
        f"and log delivery for this function is demonstrably current because the authorized "
        f"line is there too: {ran_for!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
