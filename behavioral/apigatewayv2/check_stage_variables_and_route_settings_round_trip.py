"""stage-variables-and-route-settings-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-variables-and-route-settings-round-trip"
GROUP = 'stage-deploy'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stage's StageVariables, DefaultRouteSettings and sparse per-route RouteSettings round-trip
    separately through Create/Get/Update, and DeleteRouteSettings removes only one route's override.
    """
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri="https://example.com/backend",
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    target = f"integrations/{integ_id}"
    agw.create_route(ApiId=api_id, RouteKey="GET /a", Target=target)
    agw.create_route(ApiId=api_id, RouteKey="GET /b", Target=target)
    dep_id = agw.create_deployment(ApiId=api_id)["DeploymentId"]

    stage_name = f"s{ctx.unique_name('sim2real-behav-')[-8:]}"
    default_settings = {
        "ThrottlingBurstLimit": 50,
        "ThrottlingRateLimit": 25.0,
        "DetailedMetricsEnabled": True,
    }
    route_a_settings = {
        "ThrottlingBurstLimit": 5,
        "ThrottlingRateLimit": 2.0,
        "DetailedMetricsEnabled": False,
    }
    created = agw.create_stage(
        ApiId=api_id,
        StageName=stage_name,
        DeploymentId=dep_id,
        AutoDeploy=False,
        Description="sim2real stage settings probe",
        StageVariables={"env": "test", "tableName": "t1"},
        DefaultRouteSettings=dict(default_settings),
        RouteSettings={"GET /a": dict(route_a_settings)},
    )
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName=stage_name))

    def _assert_shape(source, stage):
        variables = stage.get("StageVariables") or {}
        assert variables.get("env") == "test", f"{source} StageVariables.env: {variables}"
        assert variables.get("tableName") == "t1", f"{source} StageVariables.tableName: {variables}"
        default = stage.get("DefaultRouteSettings") or {}
        assert default.get("ThrottlingBurstLimit") == 50, (
            f"{source} DefaultRouteSettings.ThrottlingBurstLimit: {default}"
        )
        assert default.get("ThrottlingRateLimit") == 25.0, (
            f"{source} DefaultRouteSettings.ThrottlingRateLimit: {default}"
        )
        assert default.get("DetailedMetricsEnabled") is True, (
            f"{source} DefaultRouteSettings.DetailedMetricsEnabled: {default}"
        )
        per_route = stage.get("RouteSettings") or {}
        assert set(per_route) == {"GET /a"}, (
            f"{source} RouteSettings must be sparse -- only the declared 'GET /a' key, got "
            f"{sorted(per_route)}"
        )
        entry = per_route["GET /a"]
        assert entry.get("ThrottlingBurstLimit") == 5, (
            f"{source} RouteSettings['GET /a'].ThrottlingBurstLimit: {entry}"
        )
        assert entry.get("ThrottlingRateLimit") == 2.0, (
            f"{source} RouteSettings['GET /a'].ThrottlingRateLimit: {entry}"
        )
        assert entry.get("DetailedMetricsEnabled") is False, (
            f"{source} per-route DetailedMetricsEnabled must override the default (false), got "
            f"{entry}"
        )

    _assert_shape("CreateStage", created)
    _assert_shape("GetStage", agw.get_stage(ApiId=api_id, StageName=stage_name))
    listed = [s for s in agw.get_stages(ApiId=api_id).get("Items", []) if s["StageName"] == stage_name]
    assert listed, f"stage {stage_name} not in GetStages"
    _assert_shape("GetStages", listed[0])

    agw.update_stage(
        ApiId=api_id,
        StageName=stage_name,
        StageVariables={"env": "test", "tableName": "t1", "extra": "x"},
        RouteSettings={
            "GET /a": dict(route_a_settings),
            "GET /b": {"ThrottlingBurstLimit": 7, "DetailedMetricsEnabled": True},
        },
    )
    updated = agw.get_stage(ApiId=api_id, StageName=stage_name)
    variables = updated.get("StageVariables") or {}
    assert variables.get("extra") == "x", f"UpdateStage did not add the new variable: {variables}"
    assert variables.get("env") == "test" and variables.get("tableName") == "t1", (
        f"UpdateStage dropped a pre-existing stage variable: {variables}"
    )
    per_route = updated.get("RouteSettings") or {}
    assert set(per_route) == {"GET /a", "GET /b"}, (
        f"UpdateStage RouteSettings should hold both keys, got {sorted(per_route)}"
    )
    assert per_route["GET /b"].get("ThrottlingBurstLimit") == 7, (
        f"new per-route override not stored: {per_route['GET /b']}"
    )
    assert per_route["GET /a"].get("ThrottlingBurstLimit") == 5, (
        f"pre-existing per-route override changed: {per_route['GET /a']}"
    )

    agw.delete_route_settings(ApiId=api_id, StageName=stage_name, RouteKey="GET /a")
    final = agw.get_stage(ApiId=api_id, StageName=stage_name)
    per_route = final.get("RouteSettings") or {}
    assert set(per_route) == {"GET /b"}, (
        f"DeleteRouteSettings must remove only 'GET /a', RouteSettings is now {sorted(per_route)}"
    )
    default = final.get("DefaultRouteSettings") or {}
    assert default.get("ThrottlingBurstLimit") == 50, (
        f"DeleteRouteSettings must not touch DefaultRouteSettings, got {default}"
    )
    variables = final.get("StageVariables") or {}
    assert set(variables) == {"env", "tableName", "extra"}, (
        f"DeleteRouteSettings must not touch StageVariables, got {sorted(variables)}"
    )
    assert final.get("DeploymentId") == dep_id, (
        f"DeleteRouteSettings must not detach the deployment, got {final.get('DeploymentId')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
