"""import-export-reimport-api-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-export-reimport-api-round-trip"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportApi, ExportApi and ReimportApi of the export keep the route key and the integration's
    URI, type, method, payload format version and connection type; a deleted API is unreadable."""
    apigw = ctx.client("apigatewayv2")

    backend_uri = "https://example.com/"  # never invoked; a reserved documentation host
    spec = {
        "openapi": "3.0.1",
        "info": {"title": ctx.unique_name("sim2real-behav-"), "version": "1.0"},
        "paths": {
            "/pets": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "HTTP_PROXY",
                        "httpMethod": "GET",
                        "uri": backend_uri,
                        "payloadFormatVersion": "1.0",
                        "connectionType": "INTERNET",
                    },
                }
            }
        },
    }

    imported = apigw.import_api(Body=json.dumps(spec))
    api_id = imported["ApiId"]

    def _cleanup():
        try:
            apigw.delete_api(ApiId=api_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    routes_before = apigw.get_routes(ApiId=api_id)["Items"]
    assert len(routes_before) == 1, f"expected 1 route after import, got {routes_before!r}"
    assert routes_before[0]["RouteKey"] == "GET /pets", (
        f"expected route key 'GET /pets', got {routes_before[0]['RouteKey']!r}"
    )
    integration_id_before = routes_before[0]["Target"].split("/")[-1]
    integ_before = apigw.get_integration(ApiId=api_id, IntegrationId=integration_id_before)
    assert integ_before["IntegrationUri"] == backend_uri, (
        f"expected integration URI {backend_uri!r} after import, got {integ_before.get('IntegrationUri')!r}"
    )

    exported = apigw.export_api(ApiId=api_id, OutputType="JSON", Specification="OAS30")
    exported_body = exported["body"].read()

    apigw.reimport_api(ApiId=api_id, Body=exported_body.decode("utf-8"))

    routes_after = apigw.get_routes(ApiId=api_id)["Items"]
    assert len(routes_after) == 1, f"expected 1 route after reimport, got {routes_after!r}"
    assert routes_after[0]["RouteKey"] == "GET /pets", (
        f"expected route key 'GET /pets' to survive reimport, got {routes_after[0]['RouteKey']!r}"
    )
    integration_id_after = routes_after[0]["Target"].split("/")[-1]
    integ_after = apigw.get_integration(ApiId=api_id, IntegrationId=integration_id_after)
    assert integ_after["IntegrationUri"] == backend_uri, (
        f"expected integration URI {backend_uri!r} to survive reimport, got {integ_after.get('IntegrationUri')!r}"
    )

    for field in ("IntegrationType", "IntegrationMethod", "PayloadFormatVersion", "ConnectionType"):
        before_value = integ_before.get(field)
        after_value = integ_after.get(field)
        assert after_value == before_value, (
            f"expected {field} to survive the export/reimport round trip: "
            f"before={before_value!r} after={after_value!r}"
        )

    apigw.delete_api(ApiId=api_id)
    try:
        apigw.get_api(ApiId=api_id)
        raise AssertionError("expected NotFoundException reading a deleted api, but get_api succeeded")
    except apigw.exceptions.NotFoundException as exc:
        expected_message = f"Invalid API identifier specified {ctx.account}:{api_id}"
        assert exc.response["Error"]["Message"] == expected_message, exc.response["Error"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
