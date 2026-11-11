"""http-api-jwt-authorizer-rejects-foreign-issuer-and-audience."""

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

CHECK = "http-api-jwt-authorizer-rejects-foreign-issuer-and-audience"

GROUP = "authorizers"

SERVICES = ["apigatewayv2", "cognito-idp", "lambda"]

_HANDLER = """
import json
import os


def lambda_handler(event, context):
    claims = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get(
        "claims"
    ) or {}
    print("HIT " + os.environ["MARKER"] + " client_id=" + str(claims.get("client_id")))
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": os.environ["MARKER"], "claims": sorted(claims)}),
    }
"""

_PASSWORD = "Sim2Real-xsvc-1!"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A JWT authorizer refuses with 401 a valid Cognito token from another pool (issuer) or another
    client (audience), never invoking the backend, admits the configured client's token, and admits
    the second client's unchanged token once Audience is widened.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html
    """
    marker = ctx.unique_name("jwt-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"

    configured = _user_pool_with_user(ctx, label="configured")
    foreign = _user_pool_with_user(ctx, label="foreign")
    second_client = _extra_client_tokens(ctx, configured)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-jwtissuer"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    issuer = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{configured['pool_id']}"
    authorizer_id = _poll_until(
        lambda: _try_create_jwt_authorizer(ctx, api_id, issuer, [configured["client_id"]]),
        lambda r: bool(r),
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        interval_s=2.0,
        description="JWT authorizer creation (the issuer's OIDC discovery document settling)",
    )
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /guarded",
        Target=f"integrations/{integration_id}",
        AuthorizationType="JWT",
        AuthorizerId=authorizer_id,
    )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    url = _v2_invoke_url(ctx, api_endpoint, "$default", "/guarded")

    # Positive control: the configured client's token is admitted and the integration runs.
    status, _, text = _poll_http(
        url,
        accept=lambda s: s == 200,
        headers={"Authorization": f"Bearer {configured['access_token']}"},
        timeout_s=_budget_s(ctx, 180.0),
        ctx=ctx,
        interval_s=2.0,
        description="GET /guarded with a token from the configured pool and client",
    )
    assert status == 200, (
        f"the configured pool's own token must be admitted, got {status}: {text[:300]!r}"
    )
    assert json.loads(text).get("marker") == marker, (
        f"the admitted request must reach this check's backend (marker {marker!r}), got "
        f"{text[:300]!r}"
    )
    hits = _poll_until(
        lambda: _log_events_containing(ctx, log_group, f"HIT {marker}"),
        lambda msgs: bool(msgs),
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        interval_s=2.0,
        description="the integration's log line for the admitted request",
    )
    baseline = len(hits)

    # Wrong issuer: a valid, correctly signed token from another pool.
    status, _, text = _http(
        "GET", url, headers={"Authorization": f"Bearer {foreign['access_token']}"}
    )
    assert status == 401, (
        f"a correctly signed token from a DIFFERENT user pool (issuer "
        f"cognito-idp/{foreign['pool_id']}) must be refused with 401, got {status}: {text[:300]!r} "
        f"— a 200 means the target validated the token's own signature and never checked the "
        f"configured issuer"
    )
    assert "unauthorized" in text.lower(), (
        f"expected the 'Unauthorized' envelope for a failed JWT validation, got {text[:300]!r}"
    )
    baseline = _assert_backend_not_invoked(
        ctx,
        url,
        log_group,
        marker,
        baseline,
        control=configured,
        because="a token from a foreign issuer must never reach the integration",
    )

    # Wrong audience: same pool and signing key, a client id not in the Audience list.
    status, _, text = _http(
        "GET", url, headers={"Authorization": f"Bearer {second_client['access_token']}"}
    )
    assert status == 401, (
        f"a token from app client {second_client['client_id']} — same pool, same signature, but "
        f"absent from the authorizer's Audience [{configured['client_id']}] — must be refused with "
        f"401, got {status}: {text[:300]!r}"
    )
    assert "unauthorized" in text.lower(), (
        f"expected the 'Unauthorized' envelope for an audience mismatch, got {text[:300]!r}"
    )
    baseline = _assert_backend_not_invoked(
        ctx,
        url,
        log_group,
        marker,
        baseline,
        control=configured,
        because="a token whose client id is outside the Audience list must never reach the backend",
    )

    # Restore: widen the Audience (JwtConfiguration is sent whole) and the identical token succeeds.
    ctx.client("apigatewayv2").update_authorizer(
        ApiId=api_id,
        AuthorizerId=authorizer_id,
        JwtConfiguration={
            "Issuer": issuer,
            "Audience": [configured["client_id"], second_client["client_id"]],
        },
    )
    stored = agw.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    assert sorted((stored.get("JwtConfiguration") or {}).get("Audience") or []) == sorted(
        [configured["client_id"], second_client["client_id"]]
    ), (
        f"UpdateAuthorizer must store both client ids in Audience, GetAuthorizer reports "
        f"{(stored.get('JwtConfiguration') or {}).get('Audience')!r}"
    )
    status, _, text = _poll_http(
        url,
        accept=lambda s: s == 200,
        headers={"Authorization": f"Bearer {second_client['access_token']}"},
        timeout_s=_budget_s(ctx, 150.0),
        ctx=ctx,
        interval_s=2.0,
        description=(
            "the previously refused token being admitted once its client id joins the Audience "
            "(the widened authorizer config reaching the live stage)"
        ),
    )
    assert status == 200, (
        f"the same token that was refused with 401 must be admitted once its client id is in the "
        f"Audience list, got {status}: {text[:300]!r}"
    )
    _poll_until(
        lambda: len(_log_events_containing(ctx, log_group, f"HIT {marker}")),
        lambda n: n > baseline,
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        interval_s=2.0,
        description=(
            f"a new integration log line after the audience was widened (baseline {baseline})"
        ),
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _try_create_jwt_authorizer(ctx, api_id, issuer, audience):
    """CreateAuthorizer, or None while the issuer's OIDC discovery document is still settling."""
    try:
        return ctx.client("apigatewayv2").create_authorizer(
            ApiId=api_id,
            Name=_xname(ctx, "jwtauthz"),
            AuthorizerType="JWT",
            IdentitySource=["$request.header.Authorization"],
            JwtConfiguration={"Issuer": issuer, "Audience": list(audience)},
        )["AuthorizerId"]
    except ClientError:
        return None


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


def _user_pool_with_user(ctx, *, label, password=_PASSWORD):
    """A user pool + app client + one confirmed user, and that user's live tokens.

    ADMIN_USER_PASSWORD_AUTH mints tokens without a hosted UI or user-pool domain.
    """
    cog = ctx.client("cognito-idp")
    pool_id = cog.create_user_pool(
        PoolName=_xname(ctx, f"pool-{label}"),
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
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: ctx.client("cognito-idp").delete_user_pool(UserPoolId=pool_id))
    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=_xname(ctx, f"client-{label}"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    username = _xname(ctx, f"user-{label}")
    cog.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@sim2real.example"}],
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = _poll_until(
        lambda: _try_admin_auth(ctx, pool_id, client_id, username, password),
        lambda r: bool(r),
        timeout_s=90.0,
        interval_s=3.0,
        description=f"admin_initiate_auth tokens for {username}",
    )
    return {
        "pool_id": pool_id,
        "client_id": client_id,
        "username": username,
        "password": password,
        "access_token": auth["AccessToken"],
        "id_token": auth["IdToken"],
    }


def _extra_client_tokens(ctx, pool):
    """A second app client in the same pool, and tokens for the same user through it.

    Same issuer and signing key; only the `client_id` claim differs.
    """
    cog = ctx.client("cognito-idp")
    client_id = cog.create_user_pool_client(
        UserPoolId=pool["pool_id"],
        ClientName=_xname(ctx, "client-second"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    auth = _poll_until(
        lambda: _try_admin_auth(
            ctx, pool["pool_id"], client_id, pool["username"], pool["password"]
        ),
        lambda r: bool(r),
        timeout_s=90.0,
        interval_s=3.0,
        description=f"admin_initiate_auth tokens through the second app client {client_id}",
    )
    return {"client_id": client_id, "access_token": auth["AccessToken"]}


def _assert_backend_not_invoked(ctx, url, log_group, marker, baseline, *, control, because):
    """Prove "the integration did not run" by contrast: a request with the `control` client's
    token, sent after the refused one, is admitted and logged, and adds the only new log line.

    Returns the new log line count so the caller can chain legs.
    """
    control_needle = f"HIT {marker} client_id={control['client_id']}"
    control_before = len(_log_events_containing(ctx, log_group, control_needle))
    status, _, text = _http(
        "GET", url, headers={"Authorization": f"Bearer {control['access_token']}"}
    )
    assert status == 200, (
        f"the configured client's token, sent after the refused request, must be admitted, got "
        f"{status}: {text[:300]!r}"
    )
    _poll_until(
        lambda: len(_log_events_containing(ctx, log_group, control_needle)),
        lambda n: n > control_before,
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        interval_s=2.0,
        description="the integration's log line for the control request sent after the refused one",
    )
    count = len(_log_events_containing(ctx, log_group, f"HIT {marker}"))
    assert count == baseline + 1, (
        f"{because}: once the control request sent after it was logged, the integration's log "
        f"line count is {count}, expected {baseline + 1} (baseline {baseline} plus the control)"
    )
    return count


def _log_events_containing(ctx, log_group, needle):
    """Every message in log_group containing `needle`. A missing group means "no events"."""
    logs = ctx.client("logs")
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, limit=100
        ):
            for event in page.get("events", []):
                if needle in event.get("message", ""):
                    out.append(event["message"])
            if len(out) >= 50:
                break
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition", ctx=None):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=180.0,
    interval_s=4.0,
    description="invoke URL",
    ctx=None,
):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description} ({url}): the run budget ended first; not graded")
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _v2_invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of `path` on an HTTP API stage."""
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{path.lstrip('/')}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
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
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
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
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through IAM role
    propagation, then wait for Active; teardown covers role, function and its log group."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
                return None  # brand-new role not yet assumable by Lambda
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
