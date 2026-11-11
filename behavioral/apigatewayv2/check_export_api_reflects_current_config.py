"""export-api-reflects-current-config."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "export-api-reflects-current-config"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportApi reflects the API's current config, not a creation-time snapshot: an added
    route+integration appears in the next export and a removed route disappears from a later one."""
    apigw = ctx.client("apigatewayv2")

    api_id = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-api-"),
        ProtocolType="HTTP",
        Tags={"sim2real-behav": "export-api-reflects-current-config"},
    )["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    hello_integration_id = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="GET",
        IntegrationUri="https://example.com/hello",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    apigw.create_route(
        ApiId=api_id, RouteKey="GET /hello", Target=f"integrations/{hello_integration_id}"
    )

    baseline = _export_paths(apigw, api_id)
    assert "/hello" in baseline, f"expected /hello in baseline export, got paths={list(baseline)}"
    assert "/other" not in baseline, f"unexpected /other already in baseline export: {baseline}"

    other_integration_id = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="GET",
        IntegrationUri="https://example.com/other",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]

    apigw.create_route(
        ApiId=api_id, RouteKey="GET /other", Target=f"integrations/{other_integration_id}"
    )

    updated = _export_paths(apigw, api_id)
    assert "/other" in updated, f"expected /other in export after adding the route, got paths={list(updated)}"
    assert "get" in updated["/other"], updated["/other"]
    assert "/hello" in updated, "the pre-existing /hello route must still be reflected"

    # Removing the route must also be reflected -- the export is not a
    # one-way append-only cache either.
    apigw.delete_route(ApiId=api_id, RouteId=_route_id_for(apigw, api_id, "GET /other"))
    after_delete = _export_paths(apigw, api_id)
    assert "/other" not in after_delete, f"expected /other removed from export, got paths={list(after_delete)}"
    assert "/hello" in after_delete, "unrelated /hello route must remain reflected"


def _export_paths(apigw, api_id: str) -> dict:
    resp = apigw.export_api(ApiId=api_id, OutputType="JSON", Specification="OAS30")
    body = resp["body"]
    raw = body.read() if hasattr(body, "read") else body
    doc = json.loads(raw)
    return doc.get("paths", {})


def _route_id_for(apigw, api_id: str, route_key: str) -> str:
    routes = apigw.get_routes(ApiId=api_id)["Items"]
    for r in routes:
        if r["RouteKey"] == route_key:
            return r["RouteId"]
    raise AssertionError(f"route {route_key!r} not found among {routes!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
