"""jwt-authorizer-claims-reach-the-lambda-event."""

from __future__ import annotations

import base64
import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jwt-authorizer-claims-reach-the-lambda-event"

GROUP = "authorizers"

SERVICES = ["apigatewayv2", "cognito-idp", "lambda"]

_HANDLER = """
import json
import os


def lambda_handler(event, context):
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    jwt = authorizer.get("jwt") or {}
    probe = (event.get("queryStringParameters") or {}).get("probe", "")
    print("HIT " + os.environ["MARKER"] + " " + probe)
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "marker": os.environ["MARKER"],
            "claims": jwt.get("claims") or {},
            "scopes": jwt.get("scopes") or [],
        }),
    }
"""

_PASSWORD = "Sim2Real-xsvc-2!"


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:representation",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A JWT authorizer hands the integration the token's claims and scopes verbatim under
    `requestContext.authorizer.jwt` (compared field-for-field with the locally decoded token); a
    token whose `client_id` is outside the `Audience` gets 401 and never reaches the integration."""
    marker = ctx.unique_name("jwtclaims-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"

    pool = _user_pool_with_user(ctx, label="configured")
    foreign_client = _extra_client_tokens(ctx, pool)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-jwtclaims"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
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
    issuer = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool['pool_id']}"
    authorizer_id = _poll_until(
        ctx,
        lambda: _try_create_jwt_authorizer(ctx, api_id, issuer, [pool["client_id"]]),
        lambda r: bool(r),
        timeout_s=120.0,
        description="JWT authorizer creation (the issuer's OIDC discovery document settling)",
    )
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /claims",
        Target=f"integrations/{integration_id}",
        AuthorizationType="JWT",
        AuthorizerId=authorizer_id,
        AuthorizationScopes=["aws.cognito.signin.user.admin"],
    )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    url = _v2_invoke_url(ctx, api_endpoint, "$default", "/claims")

    # Positive: a valid token's claims and scope list reach the Lambda event,
    # field-for-field equal to what the SAME token decodes to locally.
    expected = _decode_jwt_payload(pool["access_token"])
    status, _, text = _poll_http(
        ctx,
        f"{url}?probe=admitted",
        accept=lambda s: s == 200,
        headers={"Authorization": f"Bearer {pool['access_token']}"},
        description="GET /claims with a valid token from the configured pool and client",
    )
    assert status == 200, (
        f"a valid token from the configured pool must be admitted, got {status}: {text[:300]!r}"
    )
    payload = json.loads(text)
    assert payload.get("marker") == marker, (
        f"the admitted request must reach this check's backend (marker {marker!r}), got "
        f"{text[:300]!r}"
    )
    claims = payload.get("claims") or {}
    for key in ("sub", "token_use", "client_id"):
        assert claims.get(key) == expected.get(key), (
            f"requestContext.authorizer.jwt.claims[{key!r}] must equal the token's own {key!r} "
            f"claim ({expected.get(key)!r}), got {claims.get(key)!r} — full claims: {claims!r}"
        )
    expected_scopes = sorted((expected.get("scope") or "").split())
    assert expected_scopes, (
        f"the minted access token carries no 'scope' claim to compare against "
        f"(decoded claims: {expected!r}) — the check's own fixture is broken, not the target"
    )
    got_scopes = sorted(payload.get("scopes") or [])
    assert got_scopes == expected_scopes, (
        f"requestContext.authorizer.jwt.scopes must equal the token's own space-delimited "
        f"'scope' claim split into a list ({expected_scopes!r}), got {got_scopes!r}"
    )

    _poll_until(
        ctx,
        lambda: _log_events_containing(ctx, log_group, f"HIT {marker} admitted"),
        lambda msgs: bool(msgs),
        timeout_s=120.0,
        description="the integration's log line for the admitted request",
    )

    # Negative: a token from a SECOND app client, outside the authorizer's
    # Audience=[configured client_id], is refused with 401 and never reaches the integration.
    status, _, text = _http(
        "GET",
        f"{url}?probe=refused",
        headers={"Authorization": f"Bearer {foreign_client['access_token']}"},
    )
    assert status == 401, (
        f"a token whose client_id {foreign_client['client_id']!r} is outside the authorizer's "
        f"Audience [{pool['client_id']!r}] must be refused with 401, got {status}: "
        f"{text[:300]!r} — a 200 means claims from an unaudited client reached the backend"
    )
    assert "unauthorized" in text.lower(), (
        f"expected the 'Unauthorized' envelope for an audience mismatch, got {text[:300]!r}"
    )

    # Positive control ordered after the refusal: an admitted request's log line lands, and by then
    # the refused request has left none.
    status, _, text = _http(
        "GET",
        f"{url}?probe=control",
        headers={"Authorization": f"Bearer {pool['access_token']}"},
    )
    assert status == 200, (
        f"a valid token sent after the refused one must still be admitted, got {status}: {text[:300]!r}"
    )
    _poll_until(
        ctx,
        lambda: _log_events_containing(ctx, log_group, f"HIT {marker} control"),
        lambda msgs: bool(msgs),
        timeout_s=120.0,
        description="the integration's log line for the admitted control request",
    )
    refused = _log_events_containing(ctx, log_group, f"HIT {marker} refused")
    assert not refused, (
        f"a token outside the Audience list must never reach the integration, but {log_group} "
        f"holds {len(refused)} log line(s) for the refused request"
    )


def _decode_jwt_payload(token: str) -> dict:
    """The unverified claims a JWT carries; no signature check, as this check minted the token."""
    segment = token.split(".")[1]
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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
        ctx,
        lambda: _try_admin_auth(ctx, pool_id, client_id, username, password),
        lambda r: bool(r),
        timeout_s=90.0,
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
    """A SECOND app client in the same pool, and tokens for the same user through it.

    Same issuer, same signing key, a different `client_id` claim — which is the only difference the
    audience leg is allowed to have.
    """
    cog = ctx.client("cognito-idp")
    client_id = cog.create_user_pool_client(
        UserPoolId=pool["pool_id"],
        ClientName=_xname(ctx, "client-second"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    auth = _poll_until(
        ctx,
        lambda: _try_admin_auth(
            ctx, pool["pool_id"], client_id, pool["username"], pool["password"]
        ),
        lambda r: bool(r),
        timeout_s=90.0,
        description=f"admin_initiate_auth tokens through the second app client {client_id}",
    )
    return {"client_id": client_id, "access_token": auth["AccessToken"]}


def _log_events_containing(ctx, log_group, needle, start_ms=None):
    """Every message in log_group containing `needle`. A missing group means "no events"."""
    logs = ctx.client("logs")
    kwargs = {"logGroupName": log_group, "limit": 100}
    if start_ms is not None:
        kwargs["startTime"] = start_ms
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(**kwargs):
            for event in page.get("events", []):
                if needle in event.get("message", ""):
                    out.append(event["message"])
            if len(out) >= 50:
                break
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout (capped by the run budget)."""
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
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


def _deadline(ctx, timeout_s):
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _poll_http(
    ctx,
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=180.0,
    interval_s=2.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
    deadline = _deadline(ctx, timeout_s)
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
    propagation, then wait for Active; tears down role, function and its log group."""
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
        ctx,
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
    _poll_until(
        ctx,
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
