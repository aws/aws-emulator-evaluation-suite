"""create-route-targeting-a-missing-integration-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-route-targeting-a-missing-integration-rejected"
GROUP = "routing"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRoute whose Target names an integration the API does not have is refused and leaves no
    route behind; the same route targeting a real integration of the API is created.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ = agw.create_integration(
        ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationMethod="GET",
        IntegrationUri="https://example.com/", PayloadFormatVersion="1.0",
    )["IntegrationId"]
    missing = "abc1234"
    assert missing != integ, "the made-up integration id collided with the real one"

    code, message = _error(lambda: agw.create_route(
        ApiId=api_id, RouteKey="GET /items", Target=f"integrations/{missing}"
    ))
    assert code == "BadRequestException", (
        f"CreateRoute to a missing integration: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == f"Unable to find route target of type integrations with ID {missing}", f"unexpected message {message!r}"
    keys = [r["RouteKey"] for r in agw.get_routes(ApiId=api_id).get("Items", [])]
    assert keys == [], f"the refused CreateRoute left routes behind: {keys!r}"

    route = agw.create_route(ApiId=api_id, RouteKey="GET /items", Target=f"integrations/{integ}")
    assert route.get("Target") == f"integrations/{integ}", f"route to a real integration: {route!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

