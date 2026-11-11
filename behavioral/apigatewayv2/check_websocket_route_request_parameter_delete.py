"""websocket-route-request-parameter-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "websocket-route-request-parameter-delete"
GROUP = 'routing'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

_TOKEN = "route.request.querystring.token"
_TENANT = "route.request.header.X-Tenant"


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRouteRequestParameter removes exactly the named parameter from a WebSocket ``$connect``
    route and keeps the others (seen via GetRoute); a second delete of the same key is
    NotFoundException with AWS's exact message."""
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ_id = agw.create_integration(ApiId=api_id, IntegrationType="MOCK")["IntegrationId"]
    route_id = agw.create_route(
        ApiId=api_id,
        RouteKey="$connect",
        AuthorizationType="NONE",
        Target=f"integrations/{integ_id}",
        RequestParameters={_TOKEN: {"Required": True}, _TENANT: {"Required": False}},
    )["RouteId"]

    got = agw.get_route(ApiId=api_id, RouteId=route_id)
    assert got.get("RequestParameters") == {_TOKEN: {"Required": True}, _TENANT: {"Required": False}}, (
        f"GetRoute must round-trip both request parameters, got {got.get('RequestParameters')!r}"
    )

    agw.delete_route_request_parameter(ApiId=api_id, RouteId=route_id, RequestParameterKey=_TOKEN)
    got = agw.get_route(ApiId=api_id, RouteId=route_id)
    assert got.get("RequestParameters") == {_TENANT: {"Required": False}}, (
        f"after deleting {_TOKEN!r} only the header parameter may remain, got "
        f"{got.get('RequestParameters')!r}"
    )
    assert got.get("RouteKey") == "$connect", f"the delete changed RouteKey: {got.get('RouteKey')!r}"
    assert got.get("Target") == f"integrations/{integ_id}", (
        f"the delete changed the route's Target: {got.get('Target')!r}"
    )

    code, message = _error(
        lambda: agw.delete_route_request_parameter(
            ApiId=api_id, RouteId=route_id, RequestParameterKey=_TOKEN
        )
    )
    assert code == "NotFoundException", (
        f"a second delete of {_TOKEN!r}: expected NotFoundException, got {code}: {message!r}"
    )
    expected = "Invalid request parameter specified"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    after = agw.get_route(ApiId=api_id, RouteId=route_id).get("RequestParameters")
    assert after == {_TENANT: {"Required": False}}, (
        f"the refused delete changed the remaining parameters: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
