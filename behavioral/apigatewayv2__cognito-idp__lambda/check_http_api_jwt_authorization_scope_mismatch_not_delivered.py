"""http-api-jwt-authorization-scope-mismatch-not-delivered."""

from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-jwt-authorization-scope-mismatch-not-delivered"

GROUP = "overly-permissive"

SERVICES = ["apigatewayv2", "cognito-idp", "lambda"]


_HANDLER = """
import json
import os


def lambda_handler(event, context):
    route = (event.get("requestContext") or {}).get("routeKey") or "?"
    path = (event.get("requestContext") or {}).get("path") or event.get("rawPath") or "?"
    print("ROUTE " + path + " " + os.environ["MARKER"])
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"route": route, "path": path}),
    }
"""

_HELD_SCOPE = "aws.cognito.signin.user.admin"
_UNHELD_SCOPE = "sim2real-api/invoke"


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """`AuthorizationScopes` is enforced per route: one Cognito AccessToken is accepted on a route whose scope it
    holds and refused with 403 on a route requiring a scope it lacks, whose integration is never invoked."""
    marker = ctx.unique_name("route-")
    pool = _user_pool_with_user(ctx)
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"

    v2 = ctx.client("apigatewayv2")
    created_api = v2.create_api(
        Name=_xname(ctx, "httpapi-scopes"),
        ProtocolType="HTTP",
        Tags=_xsvc_resource_tags(),
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]

    issuer = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool['pool_id']}"
    # The issuer's OIDC discovery document can lag pool creation, so creating the
    # authorizer is polled to success rather than attempted once.
    authorizer_id = _poll_until(
        lambda: _try_create_jwt_authorizer(ctx, api_id, issuer, pool["client_id"]),
        lambda r: bool(r),
        timeout_s=90.0,
        interval_s=5.0,
        description="JWT authorizer creation (issuer OIDC discovery)",
    )

    for path, scope in (("/admin-scope", _HELD_SCOPE), ("/api-scope", _UNHELD_SCOPE)):
        v2.create_route(
            ApiId=api_id,
            RouteKey=f"GET {path}",
            Target=f"integrations/{integration_id}",
            AuthorizationType="JWT",
            AuthorizerId=authorizer_id,
            AuthorizationScopes=[scope],
        )
    v2.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(
            ApiId=api_id, StageName="$default"
        )
    )
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*",
    )

    auth = {"Authorization": f"Bearer {pool['access_token']}"}
    start_ms = int(time.time() * 1000) - 60_000

    # Control: the route whose required scope the token DOES hold.
    ok_status, _, ok_text = _poll_http(
        _v2_invoke_url(ctx, api_endpoint, "$default", "/admin-scope"),
        accept=lambda s: s == 200,
        headers=auth,
        description="GET /admin-scope with the held scope",
    )
    assert ok_status == 200, (
        f"a token holding {_HELD_SCOPE!r} should be admitted on the route requiring it, "
        f"got {ok_status}: {ok_text!r}"
    )
    assert json.loads(ok_text).get("path", "").endswith("/admin-scope"), (
        f"control response should come from /admin-scope, got {ok_text!r}"
    )
    _poll_until(
        lambda: _log_events_containing(
            ctx, log_group, f"ROUTE /admin-scope {marker}", start_ms
        ),
        lambda msgs: bool(msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description="the control route's invocation log line",
    )

    # The negative: same token, same authorizer, a route requiring a scope it lacks.
    bad_status, _, bad_text = _http(
        "GET", _v2_invoke_url(ctx, api_endpoint, "$default", "/api-scope"), headers=auth
    )
    assert bad_status == 403, (
        f"expected 403 for a token missing the route's required scope {_UNHELD_SCOPE!r}, "
        f"got {bad_status}: {bad_text!r} (200 => the emulator verified the JWT and then "
        f"ignored AuthorizationScopes, granting every authenticated caller every route)"
    )
    assert "forbidden" in bad_text.lower(), (
        f"expected the 'Forbidden' envelope for insufficient scope, got {bad_text!r}"
    )

    _stays_absent(
        lambda: _log_events_containing(
            ctx, log_group, f"ROUTE /api-scope {marker}", start_ms
        ),
        lambda msgs: bool(msgs),
        window_s=30.0,
        interval_s=5.0,
        description=(
            f"a 'ROUTE /api-scope' log line in {log_group} (the integration running for a "
            f"request whose scope was insufficient)"
        ),
    )


def _try_create_jwt_authorizer(ctx, api_id, issuer, client_id):
    """CreateAuthorizer, or None while the issuer's OIDC discovery document settles."""
    try:
        return ctx.client("apigatewayv2").create_authorizer(
            ApiId=api_id,
            Name=_xname(ctx, "jwtauthz"),
            AuthorizerType="JWT",
            IdentitySource=["$request.header.Authorization"],
            JwtConfiguration={"Issuer": issuer, "Audience": [client_id]},
        )["AuthorizerId"]
    except ClientError:
        return None


def _user_pool_with_user(ctx, password="Sim2Real-xsvc-1!"):
    """A user pool + app client + one confirmed user, and that user's live tokens.

    Returns {pool_id, pool_arn, client_id, username, sub, id_token, access_token}.

    ADMIN_USER_PASSWORD_AUTH is used deliberately: it is the only token-minting flow that
    needs no hosted UI and no user-pool DOMAIN. The hosted-domain /oauth2/token
    client_credentials path is host-bounded on real AWS — CloudFront distribution
    propagation for a user-pool domain routinely exceeds the harness deadline. Admin auth
    keeps this check measurable on both real AWS and an emulator.
    """
    cog = ctx.client("cognito-idp")
    pool = cog.create_user_pool(
        PoolName=_xname(ctx, "pool"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        UserPoolTags=_xsvc_resource_tags(),
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(
        lambda: ctx.client("cognito-idp").delete_user_pool(UserPoolId=pool_id)
    )
    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=_xname(ctx, "client"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    username = _xname(ctx, "user")
    created = cog.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@sim2real.example"}],
    )["User"]
    sub = next(
        (a["Value"] for a in created.get("Attributes", []) if a["Name"] == "sub"), None
    )
    assert sub, f"admin_create_user returned no sub attribute: {created!r}"
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = _poll_until(
        lambda: _try_admin_auth(ctx, pool_id, client_id, username, password),
        lambda r: bool(r),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"admin_initiate_auth tokens for {username}",
    )
    return {
        "pool_id": pool_id,
        "pool_arn": pool["Arn"],
        "client_id": client_id,
        "username": username,
        "sub": sub,
        "id_token": auth["IdToken"],
        "access_token": auth["AccessToken"],
    }


def _try_admin_auth(ctx, pool_id, client_id, username, password):
    """admin_initiate_auth, or None while the just-set permanent password settles."""
    try:
        return ctx.client("cognito-idp").admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]
    except ClientError:
        return None


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on timeout. Propagation (IAM, stage deploy, log delivery) is
    always waited out this way — never with a bare time.sleep as the assertion.
    """
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
    """Assert predicate(probe()) stays FALSY for a whole bounded window.

    The negative-delivery shape: an effect that must NEVER appear is observed over a
    settle window, not with one racy read that could pass simply by being early.
    """
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


def _http(method, url, body=None, headers=None, timeout_s=20):
    """HTTP request via urllib (stdlib only). Returns (status, lower-cased headers, text).

    A 4xx/5xx is a RESULT, not an exception — negative checks assert on the status and
    body of the error response, so HTTPError is unwrapped rather than raised.
    """
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
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
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=3.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status) is true; return (status, headers, text).

    Stage/deployment/execute-api-DNS propagation is real and measured in seconds, so the
    first request through a freshly deployed stage is polled to a CONDITION with a bounded
    deadline. Connection-level errors (DNS/TLS still settling) are retried, not raised.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 - execute-api DNS/TLS settling
            last = (None, {}, "connection error")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} {url} never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:400]!r}"
    )


def _v2_invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of `path` on an HTTP API stage."""
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{path.lstrip('/')}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=None):
    """Create an IAM role and register its (policies-first) teardown. Returns {name,arn}.

    IAM propagation is real: the caller must still tolerate the first use of a brand-new
    role failing (see _create_function_with_retry / the apigateway credentials retries).
    """
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
    # IAM trust/permission propagation is real; the caller (_create_function_with_retry)
    # bounds-retries the first use of this role rather than waiting here with a flat sleep.
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


def _wait_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
):
    """Create a Lambda, RETRYING through the IAM role-propagation window, then wait Active.

    Registers the function's teardown plus its auto-created /aws/lambda/<name> log group
    (which survives function deletion and would otherwise leak).
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    while True:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                if time.monotonic() >= deadline:
                    break
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
):
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM
    statement fragments like [{"Action": ["dynamodb:PutItem"], "Resource": arn}]); logs are
    always allowed. Role + function each register their own teardown. Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    """Grant apigateway.amazonaws.com lambda:InvokeFunction, scoped to source_arn."""
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e):
            raise


def _create_log_group(ctx, kind="loggroup"):
    """Create a CloudWatch Logs group (teardown registered). Returns {name,arn}."""
    logs = ctx.client("logs")
    name = f"/sim2real/xsvc/{_xname(ctx, kind)}"
    logs.create_log_group(logGroupName=name, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=name))
    arn = f"arn:aws:logs:{ctx.region}:{_account_id(ctx)}:log-group:{name}"
    return {"name": name, "arn": arn}


def _log_events_containing(ctx, log_group, needle, start_ms=None):
    """Every message in log_group containing `needle`. A MISSING log group is 'no events',
    not an error — for a suppressed-delivery check the group legitimately never appears."""
    logs = ctx.client("logs")
    kwargs = {"logGroupName": log_group, "limit": 100}
    if start_ms is not None:
        kwargs["startTime"] = start_ms
    out = []
    try:
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(**kwargs):
            for ev in page.get("events", []):
                if needle in ev.get("message", ""):
                    out.append(ev["message"])
            if len(out) >= 20:
                break
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
