"""update-route-to-jwt-without-an-authorizer-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-route-to-jwt-without-an-authorizer-rejected"
GROUP = "authorization"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _cognito_issuer(ctx) -> str:
    """OIDC issuer of a Cognito user pool this check creates: its pool id under its endpoint.

    The check owns the issuer, so no third-party identity provider is named or contacted.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-jwt-issuer-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRoute to AuthorizationType JWT with no AuthorizerId is refused and the route stays
    unauthenticated; naming a JWT authorizer of the same API makes the same update succeed."""
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    route_id = agw.create_route(ApiId=api_id, RouteKey="GET /orders")["RouteId"]

    code, message = _error(
        lambda: agw.update_route(ApiId=api_id, RouteId=route_id, AuthorizationType="JWT")
    )
    assert code == "BadRequestException", (
        f"UpdateRoute to JWT without an authorizer: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == (
        "Invalid authorizer ID specified. Setting the authorization type to JWT requires a valid JWT "
        "authorizer."
    ), f"unexpected message {message!r}"
    route = agw.get_route(ApiId=api_id, RouteId=route_id)
    assert route.get("AuthorizationType") == "NONE", f"the refused update changed the route: {route!r}"

    authorizer_id = agw.create_authorizer(
        ApiId=api_id,
        AuthorizerType="JWT",
        IdentitySource=["$request.header.Authorization"],
        Name=ctx.unique_name("sim2real-behav-jwt-"),
        JwtConfiguration={"Audience": ["sim2real-audience"], "Issuer": _cognito_issuer(ctx)},
    )["AuthorizerId"]
    updated = agw.update_route(
        ApiId=api_id, RouteId=route_id, AuthorizationType="JWT", AuthorizerId=authorizer_id
    )
    assert (updated.get("AuthorizationType"), updated.get("AuthorizerId")) == ("JWT", authorizer_id), (
        f"UpdateRoute with an authorizer did not bind it: {updated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

