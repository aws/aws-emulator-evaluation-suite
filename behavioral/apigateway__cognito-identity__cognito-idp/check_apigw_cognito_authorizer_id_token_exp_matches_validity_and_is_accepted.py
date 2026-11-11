"""apigw-cognito-authorizer-id-token-exp-matches-validity-and-is-accepted."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-cognito-authorizer-id-token-exp-matches-validity-and-is-accepted"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]

#: IdTokenValidity configured on the app client, in seconds (the 5-minute minimum).
_VALIDITY_S = 300
#: Client/server clock skew plus request latency allowed around now + validity.
_SKEW_S = 120


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ID token from a client with IdTokenValidity 5 minutes has exp exactly iat + 300 and within
    120 s of now + 300, and a COGNITO_USER_POOLS authorizer passes it to the integration while valid.
    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html"""
    cip = ctx.client("cognito-idp")
    pool = _create_user_pool(ctx, cip)
    client_id = _create_short_lived_app_client(ctx, cip, pool["pool_id"])
    username, password = _create_confirmed_user(ctx, cip, pool["pool_id"])
    before = time.time()
    id_token = _sign_in(cip, pool["pool_id"], client_id, username, password)
    after = time.time()
    claims = _decode_jwt_claims(id_token)
    assert claims["token_use"] == "id", f"expected token_use 'id', got {claims.get('token_use')!r}"
    assert claims["aud"] == client_id, f"expected aud {client_id!r}, got {claims.get('aud')!r}"
    assert claims["exp"] - claims["iat"] == _VALIDITY_S, (
        f"exp - iat must equal the configured {_VALIDITY_S}s, got {claims['exp'] - claims['iat']}s"
    )
    low, high = before + _VALIDITY_S - _SKEW_S, after + _VALIDITY_S + _SKEW_S
    assert low <= claims["exp"] <= high, (
        f"exp {claims['exp']} must lie within {_SKEW_S}s of now + {_VALIDITY_S}s, i.e. in "
        f"[{low:.0f}, {high:.0f}]"
    )

    api = _create_rest_api_cognito_mock(
        ctx, provider_arns=[pool["pool_arn"]], response_body={"message": "still-valid"}
    )
    _wait_api_ready(api["invoke_url"])

    # Without a token the authorizer refuses; with the unexpired ID token it reaches the integration.
    status, body = _http_request(api["invoke_url"])
    assert status == 401, f"expected 401 without a token, got {status}: {body}"
    assert json.loads(body)["message"] == "Unauthorized", f"expected the gateway 'Unauthorized' body, got {body}"
    status, body = _http_request(api["invoke_url"], headers={"Authorization": id_token})
    assert status == 200, f"expected 200 for the unexpired ID token, got {status}: {body}"
    assert json.loads(body)["message"] == "still-valid", f"integration was not reached, got body: {body}"


def _create_user_pool(ctx: Any, cip: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-cog-pool-")
    pool = cip.create_user_pool(PoolName=name)["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return {"pool_id": pool_id, "pool_arn": pool["Arn"]}


def _create_short_lived_app_client(ctx: Any, cip: Any, pool_id: str) -> str:
    client = cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        IdTokenValidity=5,
        TokenValidityUnits={"IdToken": "minutes"},
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


def _sign_in(cip: Any, pool_id: str, client_id: str, username: str, password: str) -> str:
    resp = cip.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["IdToken"]


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    payload_segment = token.split(".")[1]
    payload_segment += "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_segment))


def _create_rest_api_cognito_mock(
    ctx: Any, provider_arns: list[str], response_body: dict[str, Any] | None = None
) -> dict[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
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
