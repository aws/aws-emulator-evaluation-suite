"""apigw-cognito-user-pools-authorizer-valid-token-positive."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-cognito-user-pools-authorizer-valid-token-positive"
GROUP = "authorizer-wiring"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A valid Cognito ID token passes a COGNITO_USER_POOLS authorizer and reaches the Lambda proxy integration."""
    lam_fn = _create_echo_lambda(ctx)
    pool = _create_user_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-cog-user-")
    password = "Sim2Real!Passw0rd1"
    _create_confirmed_user(ctx, pool["pool_id"], username, password)
    auth = _authenticate(ctx, pool["pool_id"], pool["client_id"], username, password)
    id_token = auth["IdToken"]

    api = _create_rest_api(ctx)
    authorizer_id = _create_cognito_authorizer(ctx, api["api_id"], [pool["pool_arn"]])
    _add_lambda_proxy_method(ctx, api["api_id"], api["root_id"], "secure", "GET", lam_fn["arn"], authorizer_id)
    base_url = _deploy(ctx, api["api_id"])
    url = f"{base_url}/secure"

    status, body = _poll_invoke_until(url, id_token, {200}, timeout_s=90, interval_s=3)
    assert status == 200, f"expected 200 with a valid ID token, got {status}: {body}"
    payload = json.loads(body)
    assert payload["source"] == "lambda-echo", "response did not come from the backing Lambda integration"
    assert payload["httpMethod"] == "GET", f"event.httpMethod should be GET, got {payload['httpMethod']!r}"
    assert payload["claims"]["cognito:username"] == username, (
        f"requestContext.authorizer.claims['cognito:username'] should be {username!r}, "
        f"got {payload['claims'].get('cognito:username')!r}"
    )


# ===== helpers =====

_LAMBDA_SRC = '''
import json
import os

def handler(event, context):
    claims = (event.get("requestContext") or {}).get("authorizer", {}).get("claims") or {}
    allowed_group = os.environ.get("ALLOWED_GROUP")
    if allowed_group:
        groups_claim = claims.get("cognito:groups") or ""
        if allowed_group not in groups_claim:
            return {"statusCode": 403, "body": json.dumps({"source": "lambda-echo", "access": "denied"})}
        return {"statusCode": 200, "body": json.dumps({"source": "lambda-echo", "access": "granted", "claims": claims})}
    return {
        "statusCode": 200,
        "body": json.dumps({
            "source": "lambda-echo",
            "httpMethod": event.get("httpMethod"),
            "path": event.get("path"),
            "claims": claims,
        }),
    }
'''


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}]


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true"}


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cog-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust, Tags=_resource_tags_kv())["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _wait_lambda_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda function {name} never became Active")


def _delete_log_group(ctx, group: str) -> None:
    """Lambda creates its log group on first write, so an absent group is already clean."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=group)
    except logs.exceptions.ResourceNotFoundException:
        return


def _create_echo_lambda(ctx, environment: dict[str, str] | None = None) -> dict[str, str]:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    name = ctx.unique_name("sim2real-cog-echo-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_bytes(_LAMBDA_SRC)},
        Timeout=10,
        Tags=_resource_tags(),
    )
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    # A new role is not assumable by Lambda until IAM propagates it: retry that error to 60 s.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    fn = None
    while fn is None:
        try:
            fn = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{name}"))
    _wait_lambda_active(ctx, name)
    return {"name": name, "arn": fn["FunctionArn"]}


def _create_user_pool_and_client(ctx, client_overrides: dict[str, Any] | None = None) -> dict[str, str]:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"), UserPoolTags=_resource_tags()
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    kwargs: dict[str, Any] = dict(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    if client_overrides:
        kwargs.update(client_overrides)
    client = idp.create_user_pool_client(**kwargs)["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    account = ctx.client("sts").get_caller_identity()["Account"]
    pool_arn = f"arn:aws:cognito-idp:{ctx.region}:{account}:userpool/{pool_id}"
    return {"pool_id": pool_id, "client_id": client_id, "pool_arn": pool_arn}


def _create_confirmed_user(ctx, pool_id: str, username: str, password: str, attributes=None) -> None:
    idp = ctx.client("cognito-idp")
    kwargs: dict[str, Any] = dict(UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS")
    if attributes:
        kwargs["UserAttributes"] = attributes
    idp.admin_create_user(**kwargs)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _authenticate(ctx, pool_id: str, client_id: str, username: str, password: str) -> dict[str, Any]:
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


def _create_rest_api(ctx) -> dict[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-cog-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=_resource_tags(),
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    return {"api_id": api_id, "root_id": root_id}


def _create_cognito_authorizer(ctx, api_id: str, provider_arns: list[str]) -> str:
    apigw = ctx.client("apigateway")
    return apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-cog-authz-"),
        type="COGNITO_USER_POOLS",
        providerARNs=provider_arns,
        identitySource="method.request.header.Authorization",
    )["id"]


def _add_lambda_proxy_method(
    ctx, api_id: str, parent_id: str, path_part: str, http_method: str, lambda_arn: str, authorizer_id: str, scopes=None
) -> str:
    apigw = ctx.client("apigateway")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)["id"]
    method_kwargs: dict[str, Any] = dict(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        authorizationType="COGNITO_USER_POOLS",
        authorizerId=authorizer_id,
    )
    if scopes:
        method_kwargs["authorizationScopes"] = scopes
    apigw.put_method(**method_kwargs)
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
    )
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    lam.add_permission(
        FunctionName=lambda_arn,
        StatementId=ctx.unique_name("sim2real-cog-perm-"),
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/{http_method}/{path_part}",
    )
    return resource_id


def _deploy(ctx, api_id: str, stage: str = "test") -> str:
    apigw = ctx.client("apigateway")
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    return ctx.rest_api_url(api_id, stage)


def _invoke(url: str, token: str | None = None, timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    if token is not None:
        req.add_header("Authorization", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _poll_invoke_until(url: str, token: str | None, target_statuses: set[int], timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status, body = _invoke(url, token)
        last = (status, body)
        if status in target_statuses:
            return status, body
        time.sleep(interval_s)
    raise AssertionError(f"never observed status in {target_statuses}; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
