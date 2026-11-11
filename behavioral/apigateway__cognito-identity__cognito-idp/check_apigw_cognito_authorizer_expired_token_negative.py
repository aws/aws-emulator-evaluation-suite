"""apigw-cognito-authorizer-expired-token-negative."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-cognito-authorizer-expired-token-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html
@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An ID token past its `exp` claim is rejected with 401 by a COGNITO_USER_POOLS authorizer and never
    reaches the integration, while the same token was accepted before it expired (5-minute minimum validity)."""
    cip = ctx.client("cognito-idp")
    pool = _create_user_pool(ctx, cip)
    client_id = _create_short_lived_app_client(ctx, cip, pool["pool_id"])
    username, password = _create_confirmed_user(ctx, cip, pool["pool_id"])
    tokens = _sign_in(cip, pool["pool_id"], client_id, username, password)
    id_token = tokens["id_token"]
    exp_epoch = _decode_jwt_exp(id_token)

    api = _create_rest_api_cognito_mock(
        ctx, provider_arns=[pool["pool_arn"]], response_body={"message": "still-valid"}
    )
    _wait_api_ready(api["invoke_url"])

    # Positive control: immediately after sign-in, the (not yet expired) token is accepted.
    status, body = _http_request(api["invoke_url"], headers={"Authorization": id_token})
    assert status == 200, f"positive control failed: expected 200, got {status}: {body}"
    positive_message = json.loads(body)["message"]
    assert positive_message == "still-valid", f"expected still-valid before expiry, got {positive_message!r}"

    # Wait out the documented minimum token-validity window, then poll for the actual
    # rejection rather than asserting exactly at the boundary (clock skew tolerance).
    while time.time() < exp_epoch + 5:
        time.sleep(5.0)

    deadline = time.monotonic() + 90.0
    last: tuple[int, str] | None = None
    while time.monotonic() < deadline:
        last = _http_request(api["invoke_url"], headers={"Authorization": id_token})
        if last[0] == 401:
            break
        time.sleep(5.0)
    assert last is not None and last[0] == 401, f"expected 401 for an expired token, got {last}"
    rejection_message = json.loads(last[1])["message"]
    # API Gateway's COGNITO_USER_POOLS authorizer distinguishes an expired token from other
    # verification failures (e.g. a signature or wrong-pool mismatch, which get the generic
    # "Unauthorized") with this specific message.
    assert rejection_message == "The incoming token has expired", (
        f"expected the specific expired-token message, got {rejection_message!r}"
    )
    assert "still-valid" not in last[1], f"integration must not have been reached, got body: {last[1]}"


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


def _sign_in(cip: Any, pool_id: str, client_id: str, username: str, password: str) -> dict[str, str]:
    resp = cip.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    result = resp["AuthenticationResult"]
    return {"id_token": result["IdToken"], "access_token": result["AccessToken"]}


def _decode_jwt_exp(token: str) -> int:
    payload_segment = token.split(".")[1]
    payload_segment += "=" * (-len(payload_segment) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_segment))
    return int(payload["exp"])


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
