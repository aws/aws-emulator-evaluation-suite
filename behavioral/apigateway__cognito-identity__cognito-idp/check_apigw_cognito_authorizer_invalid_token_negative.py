"""apigw-cognito-authorizer-invalid-token-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-cognito-authorizer-invalid-token-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A JWT with a tampered signature is rejected by the COGNITO_USER_POOLS authorizer
    with 403 and never reaches the backend integration, while the same, untampered token
    is accepted (in-file positive control)."""
    cip = ctx.client("cognito-idp")
    pool = _create_user_pool(ctx, cip)
    client_id = _create_app_client(ctx, cip, pool["pool_id"])
    username, password = _create_confirmed_user(ctx, cip, pool["pool_id"])
    tokens = _sign_in(cip, pool["pool_id"], client_id, username, password)

    api = _create_rest_api_cognito_mock(
        ctx,
        provider_arns=[pool["pool_arn"]],
        response_body={"message": "should-not-be-visible"},
    )
    _wait_api_ready(api["invoke_url"])

    # Positive control: the real, unmodified token is accepted and the request reaches
    # the backend integration.
    status, body = _http_request(api["invoke_url"], headers={"Authorization": tokens["id_token"]})
    assert status == 200, f"positive control failed: expected 200, got {status}: {body}"
    positive_message = json.loads(body)["message"]
    assert positive_message == "should-not-be-visible", f"expected the integration body, got {positive_message!r}"

    # Break exactly one thing: flip a character in the signature segment so the JWT no
    # longer verifies against the user pool's signing keys, but is otherwise well-formed.
    header, payload, signature = tokens["id_token"].split(".")
    tampered_char = "A" if signature[0] != "A" else "B"
    tampered_token = f"{header}.{payload}.{tampered_char}{signature[1:]}"

    status, body = _http_request(api["invoke_url"], headers={"Authorization": tampered_token})
    # A structurally well-formed token whose signature fails verification is denied with
    # 403 (the authorizer parsed it and rejected it on trust grounds), distinct from the
    # 401 returned for a missing/malformed identity source or an unrecognized issuer.
    assert status == 403, f"got status {status} for tampered signature (expected 403): {body[:200]}"
    assert "should-not-be-visible" not in body, f"body leaked integration response: {body[:200]}"


def _create_user_pool(ctx: Any, cip: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-cog-pool-")
    pool = cip.create_user_pool(PoolName=name, UserPoolTags={"sim2real": "true"})["UserPool"]
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


def _create_confirmed_user(ctx: Any, cip: Any, pool_id: str) -> tuple[str, str]:
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Test123"
    email = f"{username}@sim2real-test.example.com"
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
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"sim2real": "true"})["id"]
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
