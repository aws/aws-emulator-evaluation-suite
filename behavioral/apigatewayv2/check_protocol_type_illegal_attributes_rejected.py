"""protocol-type-illegal-attributes-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "protocol-type-illegal-attributes-rejected"
GROUP = 'error-semantics'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_WS_SCHEMA = '{"$schema":"http://json-schema.org/draft-04/schema#","title":"Probe","type":"object"}'


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel, a MOCK integration and RouteResponseSelectionExpression are accepted on a
    WEBSOCKET API but refused with BadRequestException on an HTTP API, leaving its state unchanged;
    the same route without the selection expression is accepted on the HTTP API.
    """
    agw = ctx.client("apigatewayv2")
    ws = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )
    ws_id = ws["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=ws_id))
    http = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    http_id = http["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=http_id))
    http_integ_id = agw.create_integration(
        ApiId=http_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri="https://example.com/backend",
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]

    # --- control legs: each attribute is legal on a WEBSOCKET API -------------------
    ws_model = agw.create_model(
        ApiId=ws_id, Name="ProbeModel", Schema=_WS_SCHEMA, ContentType="application/json"
    )
    assert ws_model.get("Name") == "ProbeModel", f"control CreateModel: {ws_model}"
    ws_mock = agw.create_integration(ApiId=ws_id, IntegrationType="MOCK")
    assert ws_mock.get("IntegrationType") == "MOCK", f"control MOCK integration: {ws_mock}"
    ws_route = agw.create_route(
        ApiId=ws_id,
        RouteKey="$default",
        AuthorizationType="NONE",
        RouteResponseSelectionExpression="$default",
        Target=f"integrations/{ws_mock['IntegrationId']}",
    )
    assert ws_route.get("RouteResponseSelectionExpression") == "$default", (
        f"control RouteResponseSelectionExpression: {ws_route}"
    )

    # --- rejection legs: the same attributes on an HTTP API -------------------------
    err = _error(
        lambda: agw.create_model(
            ApiId=http_id, Name="ProbeModel", Schema=_WS_SCHEMA, ContentType="application/json"
        )
    )
    assert err == (
        "BadRequestException",
        "Currently, Models are not permitted for APIs with a protocol type of HTTP",
    ), f"expected BadRequestException for CreateModel on an HTTP API, got {err!r}"

    err = _error(lambda: agw.create_integration(ApiId=http_id, IntegrationType="MOCK"))
    assert err == (
        "BadRequestException",
        "Currently, an API with a protocol type of HTTP may only be associated with proxy"
        " integrations (AWS_PROXY, HTTP_PROXY)",
    ), f"expected BadRequestException for a MOCK integration on an HTTP API, got {err!r}"

    err = _error(
        lambda: agw.create_route(
            ApiId=http_id,
            RouteKey="GET /rrse",
            Target=f"integrations/{http_integ_id}",
            RouteResponseSelectionExpression="$default",
        )
    )
    # AWS's message carries a doubled space before "a protocol type".
    assert err == (
        "BadRequestException",
        "Currently, a route response selection expression is not necessary for APIs with "
        " a protocol type of HTTP",
    ), (
        f"expected BadRequestException for RouteResponseSelectionExpression on an HTTP API route, "
        f"got {err!r}"
    )

    # --- effect absent on the HTTP API ---------------------------------------------
    models = agw.get_models(ApiId=http_id).get("Items", [])
    assert models == [], f"the rejected CreateModel must leave GetModels empty, got {models}"
    integ_ids = sorted(i["IntegrationId"] for i in agw.get_integrations(ApiId=http_id).get("Items", []))
    assert integ_ids == [http_integ_id], (
        f"the rejected MOCK CreateIntegration must not mint an integration, got {integ_ids}"
    )
    routes = agw.get_routes(ApiId=http_id).get("Items", [])
    assert routes == [], f"the rejected CreateRoute must leave GetRoutes empty, got {routes}"

    # --- control: the same route minus the illegal member is accepted --------------
    ok_route = agw.create_route(
        ApiId=http_id, RouteKey="GET /rrse", Target=f"integrations/{http_integ_id}"
    )
    assert ok_route.get("RouteKey") == "GET /rrse", (
        f"control: the route must be creatable without the WebSocket-only member, got {ok_route}"
    )

    final_routes = agw.get_routes(ApiId=http_id).get("Items", [])
    match = next((r for r in final_routes if r.get("RouteId") == ok_route.get("RouteId")), None)
    assert match is not None, f"the accepted control route must appear in GetRoutes, got {final_routes}"
    assert match.get("RouteKey") == "GET /rrse", f"GetRoutes RouteKey mismatch: {match}"
    assert not match.get("RouteResponseSelectionExpression"), (
        f"an HTTP API route must not acquire a RouteResponseSelectionExpression, got "
        f"{match.get('RouteResponseSelectionExpression')} via an independent GetRoutes read"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
