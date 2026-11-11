"""apigw-cognito-authorizer-wrong-user-pool-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-cognito-authorizer-wrong-user-pool-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A valid ID token issued by a user pool that is NOT in the authorizer's ProviderARNs
    is rejected with 401 and never reaches the integration, while a token from the
    configured pool is accepted (in-file positive control)."""
    cip = ctx.client("cognito-idp")
    pool_a = _create_user_pool(ctx, cip)
    client_a = _create_app_client(ctx, cip, pool_a["pool_id"])
    user_a, pass_a = _create_confirmed_user(ctx, cip, pool_a["pool_id"])
    token_a = _sign_in(cip, pool_a["pool_id"], client_a, user_a, pass_a)["id_token"]

    pool_b = _create_user_pool(ctx, cip)
    client_b = _create_app_client(ctx, cip, pool_b["pool_id"])
    user_b, pass_b = _create_confirmed_user(ctx, cip, pool_b["pool_id"])
    token_b = _sign_in(cip, pool_b["pool_id"], client_b, user_b, pass_b)["id_token"]

    # Authorizer trusts only pool A.
    api = _create_rest_api_cognito_mock(
        ctx,
        provider_arns=[pool_a["pool_arn"]],
        response_body={"message": "authorized-via-pool-a"},
    )
    _wait_api_ready(api["invoke_url"])

    # Positive control: a token issued by the configured pool is accepted.
    status, body = _http_request(api["invoke_url"], headers={"Authorization": token_a})
    assert status == 200, f"positive control failed: expected 200, got {status}: {body}"
    control_message = json.loads(body)["message"]
    assert control_message == "authorized-via-pool-a", f"expected the integration's echo, got {control_message!r}"

    # Break exactly one thing: present a token from a different, non-configured pool.
    status, body = _http_request(api["invoke_url"], headers={"Authorization": token_b})
    assert status == 401, f"expected 401 for a token from an untrusted pool, got {status}: {body}"
    rejected_message = json.loads(body)["message"]
    assert rejected_message == "Unauthorized", f"expected the gateway rejection body, got {rejected_message!r}"
    assert "authorized-via-pool-a" not in body, f"integration must never have been invoked for the rejected token, got {body}"


def _create_user_pool(ctx: Any, cip: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-cog-pool-")
    pool = cip.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog"},
    )["UserPool"]
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


def _create_confirmed_user(ctx: Any, cip: Any, pool_id: str, email: str | None = None) -> tuple[str, str]:
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Test123"
    email = email or f"{username}@sim2real-test.example.com"
    cip.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cip.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
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
    ctx: Any, provider_arns: list[str], response_body: dict[str, Any] | None = None
) -> dict[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog"},
    )["id"]
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
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": json.dumps(response_body or {"message": "forwarded"})},
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
