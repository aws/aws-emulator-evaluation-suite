"""delete-authorizer-in-use-by-a-route-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-authorizer-in-use-by-a-route-rejected"
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
    """The OIDC issuer URL of a Cognito user pool the check creates, so no third-party identity
    provider is named or contacted."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-jwt-issuer-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAuthorizer on a JWT authorizer a route still uses is refused, and the authorizer and
    the route's binding to it survive; once the route stops using it, the same delete succeeds.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    authorizer_name = ctx.unique_name("sim2real-behav-jwt-")
    authorizer_id = agw.create_authorizer(
        ApiId=api_id,
        AuthorizerType="JWT",
        IdentitySource=["$request.header.Authorization"],
        Name=authorizer_name,
        JwtConfiguration={"Audience": ["sim2real-audience"], "Issuer": _cognito_issuer(ctx)},
    )["AuthorizerId"]
    route_id = agw.create_route(
        ApiId=api_id, RouteKey="GET /secured", AuthorizationType="JWT", AuthorizerId=authorizer_id
    )["RouteId"]

    code, message = _error(lambda: agw.delete_authorizer(ApiId=api_id, AuthorizerId=authorizer_id))
    assert code == "ConflictException", (
        f"DeleteAuthorizer while a route uses it: expected ConflictException, got {code}: {message!r}"
    )
    expected = f"Cannot delete authorizer '{authorizer_name}', is referenced in route: GET /secured"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    kept = agw.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    assert kept["AuthorizerId"] == authorizer_id, f"the refused delete removed the authorizer: {kept!r}"
    route = agw.get_route(ApiId=api_id, RouteId=route_id)
    assert (route.get("AuthorizationType"), route.get("AuthorizerId")) == ("JWT", authorizer_id), (
        f"the refused delete changed the route's authorization: {route!r}"
    )

    agw.update_route(ApiId=api_id, RouteId=route_id, AuthorizationType="NONE", AuthorizerId="")
    agw.delete_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    code, message = _error(lambda: agw.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id))
    assert code == "NotFoundException", (
        f"GetAuthorizer after the delete: expected NotFoundException, got {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
