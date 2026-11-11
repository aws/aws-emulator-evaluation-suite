"""delete-integration-in-use-by-a-route-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-integration-in-use-by-a-route-rejected"
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
    """DeleteIntegration on an integration a route targets is refused and the route keeps its
    target; after the route is deleted, the same DeleteIntegration succeeds.
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
    route_id = agw.create_route(
        ApiId=api_id, RouteKey="GET /items", Target=f"integrations/{integ}"
    )["RouteId"]

    code, message = _error(lambda: agw.delete_integration(ApiId=api_id, IntegrationId=integ))
    assert code == "ConflictException", (
        f"DeleteIntegration while a route targets it: expected ConflictException, got {code}: {message!r}"
    )
    assert message == (
        f"Cannot delete Integration because it is referenced by the following Routes with Ids: "
        f"[{route_id}]"
    ), f"unexpected message {message!r}"
    assert agw.get_route(ApiId=api_id, RouteId=route_id).get("Target") == f"integrations/{integ}", (
        "the refused delete changed the route's target"
    )

    agw.delete_route(ApiId=api_id, RouteId=route_id)
    agw.delete_integration(ApiId=api_id, IntegrationId=integ)
    code, message = _error(lambda: agw.get_integration(ApiId=api_id, IntegrationId=integ))
    assert code == "NotFoundException", (
        f"GetIntegration after the delete: expected NotFoundException, got {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

