"""http-api-quick-create-synthesizes-integration-route-stage."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-quick-create-synthesizes-integration-route-stage"
GROUP = 'http-api'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApi quick create on HTTP synthesizes an integration, route and $default stage.
    WEBSOCKET quick create is accepted with Target ignored; RouteKey-only and bad Target refused.
    """
    agw = ctx.client("apigatewayv2")
    target_url = "https://example.com/backend"

    created = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-qc-"),
        ProtocolType="HTTP",
        Tags=TAGS,
        Target=target_url,
    )
    api_id = created["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    # Graded by scheme family and host; a target served over TLS publishes https.
    assert not (p := ctx.published_url_mismatch(created.get("ApiEndpoint", ""))), p
    assert created["ApiEndpoint"].startswith("https://") or not agw.meta.endpoint_url.startswith("https://"), (
        f"quick create must return an https ApiEndpoint, got {created.get('ApiEndpoint')}"
    )

    integs = agw.get_integrations(ApiId=api_id).get("Items", [])
    assert len(integs) == 1, f"quick create must synthesize exactly 1 integration, got {integs}"
    integ = integs[0]
    assert integ.get("IntegrationType") == "HTTP_PROXY", (
        f"an https Target must yield an HTTP_PROXY integration, got {integ.get('IntegrationType')}"
    )
    assert integ.get("IntegrationUri") == target_url, (
        f"synthesized IntegrationUri mismatch: {integ.get('IntegrationUri')}"
    )
    assert integ.get("PayloadFormatVersion") == "1.0", (
        f"HTTP_PROXY quick create must use PayloadFormatVersion 1.0, got "
        f"{integ.get('PayloadFormatVersion')}"
    )

    routes = agw.get_routes(ApiId=api_id).get("Items", [])
    assert len(routes) == 1, f"quick create must synthesize exactly 1 route, got {routes}"
    assert routes[0].get("RouteKey") == "$default", (
        f"with no RouteKey the catch-all $default route must be created, got "
        f"{routes[0].get('RouteKey')}"
    )
    assert routes[0].get("Target") == f"integrations/{integ['IntegrationId']}", (
        f"the synthesized route must target the synthesized integration, got "
        f"{routes[0].get('Target')}"
    )

    stages = agw.get_stages(ApiId=api_id).get("Items", [])
    assert len(stages) == 1, f"quick create must synthesize exactly 1 stage, got {stages}"
    assert stages[0].get("StageName") == "$default", (
        f"the synthesized stage must be $default, got {stages[0].get('StageName')}"
    )
    assert stages[0].get("AutoDeploy") is True, (
        f"the synthesized $default stage must have AutoDeploy=true, got "
        f"{stages[0].get('AutoDeploy')}"
    )

    keyed = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-qck-"),
        ProtocolType="HTTP",
        Tags=TAGS,
        Target=target_url,
        RouteKey="GET /qc",
    )
    keyed_id = keyed["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=keyed_id))
    keyed_routes = [r["RouteKey"] for r in agw.get_routes(ApiId=keyed_id).get("Items", [])]
    assert keyed_routes == ["GET /qc"], (
        f"quick create must honour the supplied RouteKey, got {keyed_routes}"
    )
    keyed_stages = [s["StageName"] for s in agw.get_stages(ApiId=keyed_id).get("Items", [])]
    assert keyed_stages == ["$default"], (
        f"quick create must still synthesize the $default stage, got {keyed_stages}"
    )

    # AWS does not enforce the documented HTTP-only Target: WEBSOCKET accepts it and ignores it.
    ws_name = ctx.unique_name("sim2real-behav-wsapi-qc-")
    ws = agw.create_api(
        Name=ws_name,
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
        Target=target_url,
    )
    ws_id = ws["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=ws_id))
    assert ws.get("ApiEndpoint", "").startswith("wss://"), (
        f"a WEBSOCKET API must return a wss:// endpoint, got {ws.get('ApiEndpoint')}"
    )
    assert agw.get_integrations(ApiId=ws_id).get("Items", []) == [], (
        f"Target must be ignored on a WEBSOCKET API, but an integration was synthesized: "
        f"{agw.get_integrations(ApiId=ws_id).get('Items')}"
    )
    assert agw.get_routes(ApiId=ws_id).get("Items", []) == [], (
        f"Target must be ignored on a WEBSOCKET API, but a route was synthesized: "
        f"{agw.get_routes(ApiId=ws_id).get('Items')}"
    )
    assert agw.get_stages(ApiId=ws_id).get("Items", []) == [], (
        f"Target must be ignored on a WEBSOCKET API, but a stage was synthesized: "
        f"{agw.get_stages(ApiId=ws_id).get('Items')}"
    )
    described = agw.get_api(ApiId=ws_id)
    assert "Target" not in described, (
        f"GetApi must not echo the ignored Target back, got {described.get('Target')!r}"
    )
    assert described.get("ProtocolType") == "WEBSOCKET", described

    # Leg 4 (negative): RouteKey is only meaningful as part of quick create, so it requires
    # Target on an HTTP API.
    rk_name = ctx.unique_name("sim2real-behav-httpapi-rk-")
    code, message = _error(
        lambda: agw.create_api(
            Name=rk_name, ProtocolType="HTTP", Tags=TAGS, RouteKey="GET /qc"
        )
    )
    assert code == "BadRequestException", (
        f"RouteKey without Target must be refused on an HTTP API, got {code}: {message!r}"
    )
    assert message == "Target is a required property in this context", (
        f"the refusal must name the missing property, got {message!r}"
    )

    # Leg 5 (negative): Target must resolve to one of the two supported proxy integrations.
    bad_name = ctx.unique_name("sim2real-behav-httpapi-badt-")
    code, message = _error(
        lambda: agw.create_api(
            Name=bad_name, ProtocolType="HTTP", Tags=TAGS, Target="not-a-url"
        )
    )
    assert code == "BadRequestException", (
        f"a Target that is neither an HTTP nor a Lambda proxy must be refused, got {code}: "
        f"{message!r}"
    )
    assert message == "Target only supports HTTP Proxy or Lambda Proxy", (
        f"the refusal must name what Target accepts, got {message!r}"
    )

    after = agw.get_apis().get("Items", [])
    names = [a.get("Name") for a in after]
    for refused in (rk_name, bad_name):
        assert refused not in names, (
            f"the rejected quick create must not leave an API behind: {refused}"
        )
    assert ws_name in names, (
        f"the accepted WEBSOCKET quick create must be listed: {ws_name}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
