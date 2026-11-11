"""jwt-authorizer-expired-token-rejected-never-reaches-lambda."""

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

CHECK = "jwt-authorizer-expired-token-rejected-never-reaches-lambda"

GROUP = "authorizers"

SERVICES = ["apigatewayv2", "cognito-idp", "lambda"]

#: The minimum AccessTokenValidity Cognito accepts with TokenValidityUnits=minutes (1-4 are
#: InvalidParameterException, 5 is accepted). The wait below is sized off this.
_ACCESS_TOKEN_VALIDITY_MIN = 5
#: Upper bound on how long we wait for the real transition from 200 to 401 before giving up.
_EXPIRE_WAIT_CEILING_S = 420.0

_HANDLER = """
import json
import os


def lambda_handler(event, context):
    print("HIT " + os.environ["MARKER"])
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": os.environ["MARKER"]}),
    }
"""

_PASSWORD = "Sim2Real-xsvc-3!"


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html
@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A JWT authorizer enforces the token's own `exp`: a 5-minute Cognito access token is admitted
    while fresh, then refused with 401 (never reaching the integration) once wall-clock time passes
    its validity, within a bounded window and with nothing else changed."""
    marker = ctx.unique_name("jwtexp-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"

    pool_id, client_id, access_token, mint_monotonic = _short_lived_token(ctx)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-jwtexp"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
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
    issuer = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"
    authorizer_id = _poll_until(
        lambda: _try_create_jwt_authorizer(ctx, api_id, issuer, [client_id]),
        lambda r: bool(r),
        timeout_s=120.0,
        interval_s=5.0,
        description="JWT authorizer creation (the issuer's OIDC discovery document settling)",
    )
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /expiry",
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

    url = _v2_invoke_url(ctx, api_endpoint, "$default", "/expiry")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Positive control, while the token is still fresh: admitted, and the integration
    # demonstrably runs.
    status, _, text = _poll_http(
        url, accept=lambda s: s == 200, headers=headers,
        description="GET /expiry with a freshly minted, still-valid token",
    )
    assert status == 200, (
        f"a freshly minted token (AccessTokenValidity={_ACCESS_TOKEN_VALIDITY_MIN}m) must be "
        f"admitted immediately, got {status}: {text[:300]!r}"
    )
    assert json.loads(text).get("marker") == marker, (
        f"the admitted request must reach this check's backend (marker {marker!r}), got "
        f"{text[:300]!r}"
    )
    baseline = _poll_until(
        lambda: len(_log_events_containing(ctx, log_group, f"HIT {marker}")),
        lambda n: n > 0,
        timeout_s=120.0,
        interval_s=5.0,
        description="the integration's log line for the admitted request",
    )

    # Poll the SAME endpoint with the SAME token until wall-clock time carries it past its
    # AccessTokenValidity; no API reports expiry, so the endpoint's own verdict is the poll.
    # Every sample before expiry must read 200; the first 401 is the transition.
    validity_s = _ACCESS_TOKEN_VALIDITY_MIN * 60.0
    transition_elapsed = None
    last_status, last_text = status, text
    while True:
        elapsed = time.monotonic() - mint_monotonic
        if elapsed >= _EXPIRE_WAIT_CEILING_S:
            break
        time.sleep(15.0)
        last_status, _, last_text = _http("GET", url, headers=headers)
        elapsed = time.monotonic() - mint_monotonic
        if last_status == 401:
            transition_elapsed = elapsed
            break
        assert last_status == 200, (
            f"while still within the token's validity window ({elapsed:.0f}s since mint, "
            f"declared validity {validity_s:.0f}s), expected 200, got {last_status}: "
            f"{last_text[:300]!r}"
        )

    assert transition_elapsed is not None, (
        f"the token never transitioned to a 401 within the {_EXPIRE_WAIT_CEILING_S:.0f}s "
        f"ceiling (declared validity {validity_s:.0f}s); last observed status {last_status} "
        f"{last_text[:300]!r}"
    )
    assert transition_elapsed >= validity_s - 15.0, (
        f"the token was refused at {transition_elapsed:.0f}s, before its declared "
        f"{validity_s:.0f}s validity even elapsed — an authorizer must not reject a token early"
    )
    assert "unauthorized" in last_text.lower(), (
        f"expected the 'Unauthorized' envelope for an expired token, got {last_text[:300]!r}"
    )

    # The expired token must never reach the integration from HERE ON — sampled repeatedly so a
    # target that forwards it anyway fails on the first sample rather than only at the end.
    # Re-baseline against the hit count AT the transition: the expiry polling loop legitimately
    # invoked the integration several times while the token was still fresh, and those earlier,
    # correct hits are not the thing being asserted absent.
    baseline = len(_log_events_containing(ctx, log_group, f"HIT {marker}"))
    window_s = 30.0
    deadline = time.monotonic() + window_s
    samples = 0
    while True:
        status, _, text = _http("GET", url, headers=headers)
        assert status == 401, (
            f"the SAME expired token must keep being refused, got {status}: {text[:300]!r}"
        )
        count = len(_log_events_containing(ctx, log_group, f"HIT {marker}"))
        assert count == baseline, (
            f"an expired token must never reach the integration, but the log line count rose "
            f"from {baseline} to {count} in {log_group}"
        )
        samples += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    assert samples >= 2, f"the absence window took {samples} sample(s), too few to be meaningful"


def _short_lived_token(ctx):
    """A confirmed Cognito user's live access token, minted through an app client whose
    AccessTokenValidity is the shortest real Cognito allows. Returns
    (pool_id, client_id, access_token, mint_monotonic)."""
    cog = ctx.client("cognito-idp")
    pool_id = cog.create_user_pool(
        PoolName=_xname(ctx, "pool-exp"),
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
        ClientName=_xname(ctx, "client-exp"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        AccessTokenValidity=_ACCESS_TOKEN_VALIDITY_MIN,
        TokenValidityUnits={"AccessToken": "minutes"},
    )["UserPoolClient"]["ClientId"]
    username = _xname(ctx, "user-exp")
    cog.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@sim2real.example"}],
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True
    )

    def _try_auth():
        try:
            return cog.admin_initiate_auth(
                UserPoolId=pool_id,
                ClientId=client_id,
                AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
            )["AuthenticationResult"]
        except ClientError:
            return None

    # The mint instant must be captured in the SAME moment as the auth call that returns the
    # token, because the token's exp is relative to when Cognito actually issued it.
    auth = _poll_until(
        _try_auth, lambda r: bool(r), timeout_s=90.0, interval_s=3.0,
        description=f"admin_initiate_auth tokens for {username}",
    )
    mint_monotonic = time.monotonic()
    return pool_id, client_id, auth["AccessToken"], mint_monotonic


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
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


def _poll_http(
    url, *, accept, method="GET", body=None, headers=None, timeout_s=180.0, interval_s=4.0,
    description="invoke URL",
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
