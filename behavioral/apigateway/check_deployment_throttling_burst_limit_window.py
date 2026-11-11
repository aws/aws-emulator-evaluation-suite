"""deployment-throttling-burst-limit-window."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deployment-throttling-burst-limit-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Stage throttling rate/burst limits set per method-settings key read back unchanged on
    repeated GetStage calls, and a specific-method override coexists with the wildcard default
    (both keys retained, neither merged nor overwritten)."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-throttle-"),
        tags={"sim2real": "deployment-throttling-burst-limit-window"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]

    stage_name = "sim2realbehav"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        tags={"sim2real": "deployment-throttling-burst-limit-window"},
    )
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": "100.0"},
            {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "200"},
            # A method override needs a concrete resource path: AWS rejects "*/GET" with BadRequestException;
            # the root path "/" is escaped as "~1" per the JSON-Patch convention for method-settings keys.
            {"op": "replace", "path": "/~1/GET/throttling/rateLimit", "value": "50.0"},
            {"op": "replace", "path": "/~1/GET/throttling/burstLimit", "value": "75"},
        ],
    )

    # verify twice (separate GetStage calls) that both the wildcard default and
    # the method-specific override are retained side by side and are stable.
    for _ in range(2):
        stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
        settings = stage["methodSettings"]
        assert "*/*" in settings and "~1/GET" in settings, (
            f"expected both the wildcard default key '*/*' and the method-specific "
            f"override key '~1/GET' to be retained side by side, got keys "
            f"{sorted(settings.keys())!r}"
        )
        default = settings["*/*"]
        override = settings["~1/GET"]
        assert default["throttlingRateLimit"] == 100.0, (
            f"expected the wildcard default rateLimit to remain 100.0, got "
            f"{default['throttlingRateLimit']!r}"
        )
        assert default["throttlingBurstLimit"] == 200, (
            f"expected the wildcard default burstLimit to remain 200, got "
            f"{default['throttlingBurstLimit']!r}"
        )
        assert override["throttlingRateLimit"] == 50.0, (
            f"expected the method-specific override rateLimit to remain 50.0, got "
            f"{override['throttlingRateLimit']!r}"
        )
        assert override["throttlingBurstLimit"] == 75, (
            f"expected the method-specific override burstLimit to remain 75, got "
            f"{override['throttlingBurstLimit']!r}"
        )
        # the method-specific window must differ from (be tighter than) the default
        assert override["throttlingRateLimit"] < default["throttlingRateLimit"], (
            f"expected the override rateLimit {override['throttlingRateLimit']!r} to be "
            f"tighter than the default {default['throttlingRateLimit']!r}, the wildcard "
            f"key must not have been overwritten by the specific-method patch"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
