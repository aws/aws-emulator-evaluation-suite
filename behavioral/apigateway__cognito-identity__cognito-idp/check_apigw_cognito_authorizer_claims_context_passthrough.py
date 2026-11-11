"""apigw-cognito-authorizer-claims-context-passthrough."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-cognito-authorizer-claims-context-passthrough"
GROUP = "data-format"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Identity-token claims (sub, email, cognito:groups) verified by a COGNITO_USER_POOLS
    authorizer are propagated into $context.authorizer.claims and are visible to the
    backend integration through an integration-response mapping template."""
    cip = ctx.client("cognito-idp")
    pool = _create_user_pool(ctx, cip)
    client_id = _create_app_client(ctx, cip, pool["pool_id"])
    email = f"{ctx.unique_name('sim2real-user-')}@example.com"
    username, password = _create_confirmed_user(ctx, cip, pool["pool_id"], email=email, group="sim2real-admins")
    tokens = _sign_in(cip, pool["pool_id"], client_id, username, password)
    # Fetch the immutable `sub` attribute directly so we compare against ground truth,
    # not a value derived from the same token we're about to validate.
    attrs = {a["Name"]: a["Value"] for a in cip.get_user(AccessToken=tokens["access_token"])["UserAttributes"]}
    expected_sub = attrs["sub"]

    claims_template = (
        "{"
        '"sub":"$context.authorizer.claims.sub",'
        '"email":"$context.authorizer.claims.email",'
        '"groups":"$util.escapeJavaScript($context.authorizer.claims.get(\'cognito:groups\'))"'
        "}"
    )
    api = _create_rest_api_cognito_mock(
        ctx, provider_arns=[pool["pool_arn"]], response_template=claims_template
    )
    _wait_api_ready(api["invoke_url"])

    status, body = _http_request(api["invoke_url"], headers={"Authorization": tokens["id_token"]})
    assert status == 200, f"expected 200, got {status}: {body}"
    claims = json.loads(body)
    assert claims["sub"] == expected_sub, f"expected claims.sub {expected_sub!r}, got {claims['sub']!r}"
    assert claims["email"] == email, f"expected claims.email {email!r}, got {claims['email']!r}"
    assert "sim2real-admins" in claims["groups"], (
        f"expected 'sim2real-admins' in claims.groups, got {claims['groups']!r}"
    )


def _create_user_pool(ctx: Any, cip: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-cog-pool-")
    pool = cip.create_user_pool(PoolName=name, UserPoolTags={"sim2real": CHECK})["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return {"pool_id": pool_id, "pool_arn": pool["Arn"]}


def _create_app_client(ctx: Any, cip: Any, pool_id: str) -> str:
    client = cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    return client["ClientId"]


def _create_confirmed_user(ctx: Any, cip: Any, pool_id: str, email: str, group: str) -> tuple[str, str]:
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Test123"
    cip.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email_verified", "Value": "true"},
            {"Name": "email", "Value": email},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cip.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    cip.create_group(UserPoolId=pool_id, GroupName=group)
    cip.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
    return username, password


def _sign_in(cip: Any, pool_id: str, client_id: str, username: str, password: str) -> dict[str, str]:
    resp = cip.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    result = resp["AuthenticationResult"]
    return {"id_token": result["IdToken"], "access_token": result["AccessToken"]}


def _create_rest_api_cognito_mock(
    ctx: Any,
    provider_arns: list[str],
    authorization_scopes: list[str] | None = None,
    response_template: str | None = None,
) -> dict[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authz-"),
        type="COGNITO_USER_POOLS",
        providerARNs=provider_arns,
        identitySource="method.request.header.Authorization",
    )["id"]
    method_kwargs: dict[str, Any] = dict(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="COGNITO_USER_POOLS",
        authorizerId=authorizer_id,
    )
    if authorization_scopes:
        method_kwargs["authorizationScopes"] = authorization_scopes
    apigw.put_method(**method_kwargs)
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    template = response_template or json.dumps({"message": "forwarded"})
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": template},
    )
    apigw.create_deployment(restApiId=api_id, stageName="sim2real")
    invoke_url = f"{ctx.rest_api_url(api_id, 'sim2real')}/widgets"
    return {"api_id": api_id, "invoke_url": invoke_url}


def _http_request(
    url: str, method: str = "GET", headers: dict[str, str] | None = None, data: bytes | None = None, timeout: float = 15.0
) -> tuple[int, str]:
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _wait_api_ready(url: str, timeout_s: float = 45.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: tuple[int, str] | None = None
    while time.monotonic() < deadline:
        last = _http_request(url)
        if last[0] == 401:
            return
        time.sleep(interval_s)
    raise AssertionError(f"API never became ready (last response={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
