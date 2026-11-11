"""apigw-cognito-authorizer-missing-token-not-delivered."""

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

CHECK = "apigw-cognito-authorizer-missing-token-not-delivered"

GROUP = "overly-permissive"

SERVICES = ["apigateway", "cognito-idp", "lambda"]


_HANDLER = """
import json
import os


def lambda_handler(event, context):
    # The single observable that distinguishes 'rejected at the gateway' from
    # 'rejected in the response but the backend already ran'.
    print("BACKEND-INVOKED " + os.environ["MARKER"])
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": os.environ["MARKER"]}),
    }
"""


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A COGNITO_USER_POOLS method answers 401 Unauthorized to a request with no Authorization header and to one
    with an invalid token and invokes the backend in neither case, while a real IdToken returns 200 and invokes it;
    an authorizer that lets a request through would expose a private API."""
    marker = ctx.unique_name("backend-")
    pool = _user_pool_with_user(ctx)
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw-cognito-neg")
    authorizer_id = ag.create_authorizer(
        restApiId=api_id,
        name=_xname(ctx, "cogauthz"),
        type="COGNITO_USER_POOLS",
        providerARNs=[pool["pool_arn"]],
        identitySource="method.request.header.Authorization",
    )["id"]
    res_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")[
        "id"
    ]
    ag.put_method(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        authorizationType="COGNITO_USER_POOLS",
        authorizerId=authorizer_id,
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )
    _allow_apigw_invoke(
        ctx,
        fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*",
    )
    _deploy_stage(ctx, api_id, "test")

    url = _rest_invoke_url(ctx, api_id, "test", "/secure")
    start_ms = int(time.time() * 1000) - 60_000

    # (a) no Authorization header at all.
    no_token_status, _, no_token_text = _poll_http(
        url,
        accept=lambda s: s in (200, 401, 403),
        description="unauthenticated GET /secure",
    )
    assert no_token_status == 401, (
        f"expected 401 for a request with no Authorization header on a "
        f"COGNITO_USER_POOLS method, got {no_token_status}: {no_token_text!r} "
        f"(2xx => the emulator let an unauthenticated request reach the backend)"
    )
    assert "unauthorized" in no_token_text.lower(), (
        f"expected API Gateway's 'Unauthorized' envelope, got {no_token_text!r}"
    )

    # (b) a token-shaped string that is not a pool token.
    bad_status, _, bad_text = _http(
        "GET", url, headers={"Authorization": "Bearer not-a-real-jwt.at.all"}
    )
    assert bad_status == 401, (
        f"expected 401 for an unverifiable bearer token, got {bad_status}: {bad_text!r} "
        f"(2xx => the emulator admitted an arbitrary string as a valid pool token)"
    )

    # The effect that must never appear: the backend running for either rejected request.
    _stays_absent(
        lambda: _log_events_containing(
            ctx, log_group, f"BACKEND-INVOKED {marker}", start_ms
        ),
        lambda msgs: bool(msgs),
        # At least as long as the control's confirmed-delivery timeout below (120s), never shorter.
        # An absence window narrower than the window in which delivery is known to be observable is
        # unsound: Lambda log delivery routinely exceeds 30s, so a backend that WAS wrongly invoked
        # could emit its line at 40-90s -- after a 30s window closed, but inside the control's 120s
        # -- and both legs would pass. That is a false pass on the exact over-permissiveness this
        # check exists to catch.
        window_s=120.0,
        interval_s=5.0,
        description=(
            f"a BACKEND-INVOKED log line in {log_group} (the backend Lambda running for "
            f"a request the Cognito authorizer rejected)"
        ),
    )

    # Control: the identical request with a real IdToken.
    ok_status, _, ok_text = _poll_http(
        url,
        accept=lambda s: s == 200,
        headers={"Authorization": pool["id_token"]},
        description="authenticated GET /secure",
    )
    assert ok_status == 200, (
        f"control: a valid IdToken should reach the backend, got {ok_status}: {ok_text!r}"
    )
    assert json.loads(ok_text).get("marker") == marker, (
        f"control response should carry the backend marker {marker!r}, got {ok_text!r}"
    )
    _poll_until(
        lambda: _log_events_containing(
            ctx, log_group, f"BACKEND-INVOKED {marker}", start_ms
        ),
        lambda msgs: bool(msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            "the control invocation's BACKEND-INVOKED log line (proves the absence "
            "asserted above was the authorizer's decision, not a broken observation)"
        ),
    )


def _user_pool_with_user(ctx, password="Sim2Real-xsvc-1!"):
    """A user pool + app client + one confirmed user, and that user's live tokens.

    Returns {pool_id, pool_arn, client_id, username, sub, id_token, access_token}.

    ADMIN_USER_PASSWORD_AUTH needs no hosted UI and no user-pool domain.
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


def _rest_invoke_url(ctx, api_id, stage, path):
    """The invoke URL of a DEPLOYED REST API stage, from ``ctx.rest_api_url``.

    Real AWS: ``https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>``; under an
    emulator, the ``/_aws/execute-api/<id>/<stage>/<path>`` route (see ctx.rest_api_url).
    """
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _create_rest_api(ctx, kind="api", **extra):
    """Create a REGIONAL REST API (teardown registered) and return (api_id, root_resource_id)."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=_xname(ctx, kind),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=_xsvc_resource_tags(),
        **extra,
    )["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage, variables=None, **extra):
    """CreateDeployment + CreateStage. Returns the deployment id.

    Deployment and stage are separate on purpose: several checks put two stages on ONE
    deployment to isolate a per-stage setting as the only variable.
    """
    ag = ctx.client("apigateway")
    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    kwargs = {"restApiId": api_id, "stageName": stage, "deploymentId": dep_id}
    if variables:
        kwargs["variables"] = variables
    kwargs.update(extra)
    ag.create_stage(**kwargs)
    ctx.on_cleanup(
        lambda: ctx.client("apigateway").delete_stage(restApiId=api_id, stageName=stage)
    )
    return dep_id


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
