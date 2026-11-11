"""create-route-and-integration."""
from __future__ import annotations

from behavioral_harness import tags

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

CHECK = "create-route-and-integration"
GROUP = 'routing'
SERVICES = ['apigatewayv2']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIntegration + CreateRoute wire together; GetRoute/GetIntegration reflect it."""
    agw = ctx.client("apigatewayv2")
    _api = agw.create_api(Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=_api["ApiId"]))
    api_id = _api["ApiId"]

    integ = agw.create_integration(ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationUri="https://example.com/backend", IntegrationMethod="GET", PayloadFormatVersion="1.0")
    integ_id = integ["IntegrationId"]

    route_key = "GET /items"
    route = agw.create_route(
        ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integ_id}"
    )
    route_id = route["RouteId"]

    got_route = agw.get_route(ApiId=api_id, RouteId=route_id)
    assert got_route["RouteKey"] == route_key, f"route key mismatch: {got_route.get('RouteKey')}"
    assert got_route["Target"] == f"integrations/{integ_id}", (
        f"route target does not reference integration: {got_route.get('Target')}"
    )

    got_integ = agw.get_integration(ApiId=api_id, IntegrationId=integ_id)
    assert got_integ["IntegrationType"] == "HTTP_PROXY", (
        f"integration type mismatch: {got_integ.get('IntegrationType')}"
    )
    assert got_integ["IntegrationUri"] == "https://example.com/backend", (
        f"integration uri mismatch: {got_integ.get('IntegrationUri')}"
    )
    assert got_integ["IntegrationMethod"] == "GET", (
        f"integration method mismatch: {got_integ.get('IntegrationMethod')}"
    )
    assert got_integ["PayloadFormatVersion"] == "1.0", (
        f"payload format version mismatch: {got_integ.get('PayloadFormatVersion')}"
    )

    listed_routes = agw.get_routes(ApiId=api_id)
    assert any(r["RouteId"] == route_id for r in listed_routes.get("Items", [])), (
        f"route {route_id} not in GetRoutes: {listed_routes.get('Items')}"
    )
    listed_integs = agw.get_integrations(ApiId=api_id)
    assert any(i["IntegrationId"] == integ_id for i in listed_integs.get("Items", [])), (
        f"integration {integ_id} not in GetIntegrations: {listed_integs.get('Items')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
