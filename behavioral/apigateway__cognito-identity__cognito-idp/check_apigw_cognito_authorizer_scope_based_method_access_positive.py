"""apigw-cognito-authorizer-scope-based-method-access-positive."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-cognito-authorizer-scope-based-method-access-positive"
GROUP = "event-propagation"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An OAuth access token carrying a custom resource-server scope that is declared in
    the method's AuthorizationScopes is treated as an access token by the authorizer and
    is permitted through to the integration."""
    # Provisioning a Cognito domain (which stands up a dedicated CloudFront distribution)
    # and completing a client-credentials grant against it takes several minutes, and it
    # happens on every backend -- real AWS included. An unset cost opt-in recorded this
    # check as passed without ever minting a token, so the minutes were "saved" by not
    # testing the scope-authorization path at all.
    cip = ctx.client("cognito-idp")
    pool = _create_user_pool(ctx, cip)
    resource_server_id = f"https://{ctx.unique_name('sim2real-rs-')}"
    cip.create_resource_server(
        UserPoolId=pool["pool_id"],
        Identifier=resource_server_id,
        Name="sim2real-resource-server",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    full_scope = f"{resource_server_id}/read"
    client_id, client_secret = _create_m2m_app_client(ctx, cip, pool["pool_id"], full_scope)
    domain_prefix = _create_and_wait_domain(ctx, cip, pool["pool_id"])

    access_token = _client_credentials_token(ctx, domain_prefix, client_id, client_secret, full_scope)

    api = _create_rest_api_cognito_mock(
        ctx,
        provider_arns=[pool["pool_arn"]],
        authorization_scopes=[full_scope],
        response_body={"message": "scope-authorized"},
    )
    _wait_api_ready(api["invoke_url"])

    status, body = _http_request(api["invoke_url"], headers={"Authorization": access_token})
    assert status == 200, f"expected 200 for a token carrying the required scope, got {status}: {body}"
    reached = json.loads(body)["message"]
    assert reached == "scope-authorized", f"expected the request to reach the integration, got {reached!r}"


def _create_user_pool(ctx: Any, cip: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-cog-pool-")
    pool = cip.create_user_pool(PoolName=name)["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return {"pool_id": pool_id, "pool_arn": pool["Arn"]}


def _create_m2m_app_client(ctx: Any, cip: Any, pool_id: str, full_scope: str) -> tuple[str, str]:
    client = cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-m2m-"),
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[full_scope],
        AllowedOAuthFlowsUserPoolClient=True,
        SupportedIdentityProviders=["COGNITO"],
    )["UserPoolClient"]
    return client["ClientId"], client["ClientSecret"]


def _create_and_wait_domain(ctx: Any, cip: Any, pool_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> str:
    domain_prefix = ctx.unique_name("sim2real-dom-").lower()
    cip.create_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cip.delete_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id))
    # A user pool domain provisions a dedicated CloudFront distribution behind the scenes
    # and is not immediately usable; poll DescribeUserPoolDomain for the real ACTIVE
    # condition rather than assuming any fixed provisioning time.
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = cip.describe_user_pool_domain(Domain=domain_prefix)["DomainDescription"]
        last_status = desc.get("Status")
        if last_status == "ACTIVE":
            return domain_prefix
        time.sleep(interval_s)
    raise AssertionError(f"user pool domain never reached ACTIVE (last status={last_status})")


def _client_credentials_token(ctx: Any, domain_prefix: str, client_id: str, client_secret: str, scope: str) -> str:
    base_url, route_headers = f"https://{domain_prefix}.auth.{ctx.region}.amazoncognito.com", {}
    token_url = f"{base_url}/oauth2/token"
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client_id, "scope": scope}).encode()
    headers = {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
        **route_headers,
    }
    # The token endpoint sits behind the same freshly-provisioned domain. DescribeUserPoolDomain
    # reporting ACTIVE does not mean the domain's DNS record has propagated: measured on real AWS
    # the token endpoint took ~300s to become resolvable after ACTIVE, so this is not a brief retry
    # -- it is the dominant wait of the whole check.
    deadline = time.monotonic() + 600.0
    last: tuple[int, str] | None = None
    while time.monotonic() < deadline:
        status, resp_body = _http_request(token_url, method="POST", headers=headers, data=body)  # customer-built AWS host
        last = (status, resp_body)
        if status == 200:
            return json.loads(resp_body)["access_token"]
        time.sleep(5.0)
    raise AssertionError(f"client_credentials token request never succeeded (last={last})")


def _create_rest_api_cognito_mock(
    ctx: Any,
    provider_arns: list[str],
    authorization_scopes: list[str] | None = None,
    response_body: dict[str, Any] | None = None,
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
    except urllib.error.URLError as exc:
        # DescribeUserPoolDomain reporting ACTIVE does not guarantee the domain's DNS record has
        # propagated yet: the connection can still fail with "Name or service not known" for a
        # short window right after. That is the "just before fully consistent" case the retry
        # loops below already budget for -- surface it as a retryable non-2xx rather than letting
        # the raw URLError escape and abort the retry.
        return 0, str(exc.reason)


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
