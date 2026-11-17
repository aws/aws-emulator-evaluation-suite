"""update-route-response-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-route-response-nonexistent-not-found"
GROUP = "responses"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRouteResponse on a route response id that was deleted fails NotFoundException,
    while the identical call on a sibling route response of the same route still succeeds."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-urrnf-"),
        ProtocolType="WEBSOCKET",
        Tags=TAGS,
        RouteSelectionExpression="$request.body.action",
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    live_route_id = agw.create_route(
        ApiId=api_id, RouteKey="liveAction", RouteResponseSelectionExpression="$default"
    )["RouteId"]
    live_rr_id = agw.create_route_response(
        ApiId=api_id, RouteId=live_route_id, RouteResponseKey="$default"
    )["RouteResponseId"]
    ctx.on_cleanup(
        lambda: agw.delete_route_response(ApiId=api_id, RouteId=live_route_id, RouteResponseId=live_rr_id)
    )

    doomed_route_id = agw.create_route(
        ApiId=api_id, RouteKey="deadAction", RouteResponseSelectionExpression="$default"
    )["RouteId"]
    doomed_rr_id = agw.create_route_response(
        ApiId=api_id, RouteId=doomed_route_id, RouteResponseKey="$default"
    )["RouteResponseId"]
    agw.delete_route_response(ApiId=api_id, RouteId=doomed_route_id, RouteResponseId=doomed_rr_id)

    code, message = _error(
        lambda: agw.update_route_response(
            ApiId=api_id,
            RouteId=doomed_route_id,
            RouteResponseId=doomed_rr_id,
            ModelSelectionExpression="$request.body.type",
        )
    )
    assert code == "NotFoundException", (
        f"UpdateRouteResponse on a deleted route response: expected NotFoundException, "
        f"got {code}: {message!r}"
    )
    assert message == "Invalid route response specified", (
        f"UpdateRouteResponse on a deleted route response: unexpected message {message!r}"
    )

    # positive control: the sibling route response on a different route still accepts the update.
    agw.update_route_response(
        ApiId=api_id,
        RouteId=live_route_id,
        RouteResponseId=live_rr_id,
        ModelSelectionExpression="$request.body.type",
    )
    fetched = agw.get_route_response(ApiId=api_id, RouteId=live_route_id, RouteResponseId=live_rr_id)
    assert fetched.get("ModelSelectionExpression") == "$request.body.type", (
        f"UpdateRouteResponse on the live sibling did not take effect: "
        f"{fetched.get('ModelSelectionExpression')!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
