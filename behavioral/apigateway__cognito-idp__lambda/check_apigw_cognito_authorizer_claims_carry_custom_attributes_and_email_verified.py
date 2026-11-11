"""apigw-cognito-authorizer-claims-carry-custom-attributes-and-email-verified."""

from __future__ import annotations

import io
import json
import ssl
import textwrap
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-cognito-authorizer-claims-carry-custom-attributes-and-email-verified"
GROUP = "data-format"
SERVICES = ["apigateway", "cognito-idp", "lambda"]

_PASSWORD = "Sim2Real!Passw0rd1"
_TIER = "sim2real-gold"
_LEVEL = "42"

_HANDLER = """\
import json


def handler(event, context):
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    return {"statusCode": 200, "body": json.dumps({"claims": authorizer.get("claims")})}
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A REST API Cognito authorizer passes custom:* and email_verified claims to the Lambda.

    requestContext.authorizer.claims carries custom:tier, custom:level and email_verified with
    their ID-token values as strings ("42", "true").

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html
    """
    idp = ctx.client("cognito-idp")
    ids: dict[str, str] = {}
    ctx.on_cleanup(
        _teardown(
            lambda: "pool" in ids and idp.delete_user_pool(UserPoolId=ids["pool"]),
            "ResourceNotFoundException",
        )
    )
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cog-pool-"),
        Schema=[
            {"Name": "tier", "AttributeDataType": "String", "Mutable": True},
            {"Name": "level", "AttributeDataType": "Number", "Mutable": True},
        ],
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]
    pool_id = ids["pool"] = pool["Id"]
    pool_arn = pool["Arn"]
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cog-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-cog-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "custom:tier", "Value": _TIER},
            {"Name": "custom:level", "Value": _LEVEL},
        ],
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True
    )
    id_token = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]["IdToken"]

    lam = ctx.client("lambda")
    fn = _function(ctx, lam, "python3.12", _role_arn(ctx), _make_zip(_HANDLER))
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    url = _api_with_cognito_method(ctx, pool_arn, fn, fn_arn)

    tls = _ssl_context(ctx.http_verify)
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    status, body = _get(url, id_token, tls)
    while status != 200 and time.monotonic() < deadline:
        time.sleep(3)
        status, body = _get(url, id_token, tls)
    if status != 200 and _budget_spent(ctx):
        raise TimeoutError(f"run budget ended before the stage served 200; last {status}")
    assert status == 200, f"expected 200 with a valid ID token, got {status}: {body[:300]}"
    claims = json.loads(body)["claims"]
    assert isinstance(claims, dict), f"claims did not arrive as a map: {claims!r}"
    want = {"custom:tier": _TIER, "custom:level": _LEVEL, "email_verified": "true"}
    got = {k: claims.get(k) for k in want}
    assert got == want, f"authorizer claims were {got!r}, expected {want!r}; all: {claims!r}"


def _api_with_cognito_method(ctx, pool_arn: str, fn: str, fn_arn: str) -> str:
    """A REST API whose GET /secure is a Cognito-authorized Lambda proxy; returns its URL."""
    apigw = ctx.client("apigateway")
    partition, account = fn_arn.split(":")[1], fn_arn.split(":")[4]
    ids: dict[str, str] = {}
    ctx.on_cleanup(
        _teardown(
            lambda: "api" in ids and apigw.delete_rest_api(restApiId=ids["api"]),
            "NotFoundException",
        )
    )
    api_id = ids["api"] = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-cog-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-cog-authz-"),
        type="COGNITO_USER_POOLS",
        providerARNs=[pool_arn],
        identitySource="method.request.header.Authorization",
    )["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")["id"]
    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="COGNITO_USER_POOLS",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:{partition}:apigateway:{ctx.region}:lambda:path/2015-03-31/"
        f"functions/{fn_arn}/invocations",
    )
    ctx.client("lambda").add_permission(
        FunctionName=fn,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:{partition}:execute-api:{ctx.region}:{account}:{api_id}/*/GET/secure",
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")
    return f"{ctx.rest_api_url(api_id, 'test')}/secure"


def _ssl_context(verify):
    """The TLS context for ``ctx.http_verify``: a CA bundle path, True, or False if exempt."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _get(url: str, token: str, tls) -> tuple[int | None, str]:
    """GET url as ``(status, body)``; ``(None, reason)`` while the new host does not answer."""
    req = urllib.request.Request(url, method="GET", headers={"Authorization": token})
    try:
        with urllib.request.urlopen(req, timeout=10, context=tls) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except urllib.error.URLError as exc:
        return None, f"no response: {exc.reason}"


# ===== helpers =====
def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _role_arn(ctx) -> str:
    """An execution role allowed to write its logs; deleted in cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"), "NoSuchEntity")
    )
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    return arn


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush and recreate the group after delete_function returns, so
    one delete is one round, not a teardown.
    """
    logs = ctx.client("logs")
    budget = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + budget
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget:.0f}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


def _function(ctx, lam, runtime, role, code) -> str:
    """Create a function, retried while its new role propagates, and wait until it is Active."""
    name = ctx.unique_name(f"sim2real-behav-{runtime.replace('.', '')}-")
    # LIFO: the log group is reaped after the function itself is deleted.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")
    )
    kwargs = dict(
        FunctionName=name,
        Runtime=runtime,
        Handler="index.handler",
        Role=role,
        Code={"ZipFile": code},
        MemorySize=128,
        Timeout=30,
        Architectures=["x86_64"],
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while creating {name}: {exc}") from exc
            raise
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {name} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return name
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"run budget ended before {name} was Active")
    raise AssertionError(f"{name} Active not met within the wait. Last: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
