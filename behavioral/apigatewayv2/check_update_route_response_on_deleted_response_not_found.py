"""update-route-response-on-deleted-response-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-route-response-on-deleted-response-not-found"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRouteResponse on a RouteResponseId that DeleteRouteResponse already removed fails
    NotFoundException, while the same update against a sibling route response still succeeds."""
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    route_id = agw.create_route(
        ApiId=api_id, RouteKey="$default", RouteResponseSelectionExpression="$default"
    )["RouteId"]

    dead = agw.create_route_response(ApiId=api_id, RouteId=route_id, RouteResponseKey="$default")
    dead_id = dead["RouteResponseId"]

    agw.delete_route_response(ApiId=api_id, RouteId=route_id, RouteResponseId=dead_id)

    code, message = _error(
        lambda: agw.update_route_response(
            ApiId=api_id,
            RouteId=route_id,
            RouteResponseId=dead_id,
            ModelSelectionExpression="$request.body.type",
        )
    )
    assert code == "NotFoundException", (
        f"UpdateRouteResponse on a deleted RouteResponseId: expected NotFoundException, "
        f"got {code}: {message!r}"
    )
    expected = "Invalid route response specified"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the dead id is still not retrievable; the refused update created nothing.
    absent_code, absent_message = _error(
        lambda: agw.get_route_response(ApiId=api_id, RouteId=route_id, RouteResponseId=dead_id)
    )
    assert absent_code == "NotFoundException", (
        f"GetRouteResponse on the dead id: expected NotFoundException, got {absent_code}: "
        f"{absent_message!r}"
    )

    # A second WebSocket route, with its own live route response, is a legal neighbour: the same
    # UpdateRouteResponse shape against it succeeds.
    control_route_id = agw.create_route(
        ApiId=api_id, RouteKey="controlRoute", RouteResponseSelectionExpression="$default"
    )["RouteId"]
    control_id = agw.create_route_response(
        ApiId=api_id, RouteId=control_route_id, RouteResponseKey="$default"
    )["RouteResponseId"]
    updated = agw.update_route_response(
        ApiId=api_id,
        RouteId=control_route_id,
        RouteResponseId=control_id,
        ModelSelectionExpression="$request.body.type",
    )
    assert updated.get("ModelSelectionExpression") == "$request.body.type", (
        f"the control update on a live route response did not apply: {updated!r}"
    )
    got_control = agw.get_route_response(
        ApiId=api_id, RouteId=control_route_id, RouteResponseId=control_id
    )
    assert got_control.get("ModelSelectionExpression") == "$request.body.type", (
        f"independent read did not reflect the control update: {got_control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
