"""create-route-response-invalid-route-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-route-response-invalid-route-rejected"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteResponse against a RouteId that does not exist on the API is
    rejected with NotFoundException, no route response is created, and the
    SAME call against the real route still succeeds."""
    apigw = ctx.client("apigatewayv2")

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-ws-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    route = apigw.create_route(ApiId=api_id, RouteKey="$default")
    route_id = route["RouteId"]

    # Break: attempt to create a route response against a RouteId that was
    # never created on this API.
    bogus_route_id = "bogus" + ctx.unique_name("rt")
    code, message = _error_code(
        lambda: apigw.create_route_response(
            ApiId=api_id, RouteId=bogus_route_id, RouteResponseKey="$default"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_message = "Invalid route identifier specified"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Effect absent: no route response exists on the bogus route id (it
    # doesn't exist), and the real route still has zero route responses.
    items = apigw.get_route_responses(ApiId=api_id, RouteId=route_id)["Items"]
    assert items == [], f"expected no route responses on the real route, got {items!r}"

    # Positive control: the SAME request against the real route succeeds.
    control = apigw.create_route_response(
        ApiId=api_id, RouteId=route_id, RouteResponseKey="$default"
    )
    assert control["RouteResponseKey"] == "$default", (
        f"expected control create to report RouteResponseKey='$default', got {control!r}"
    )
    got_control = apigw.get_route_response(
        ApiId=api_id, RouteId=route_id, RouteResponseId=control["RouteResponseId"]
    )
    assert got_control["RouteResponseKey"] == "$default", (
        f"expected the independent read to confirm RouteResponseKey='$default', got {got_control!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises.
    Throttling is retried."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

