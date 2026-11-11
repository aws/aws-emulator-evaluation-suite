"""stage-cache-ttl-zero-disables-caching-immediately."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "stage-cache-ttl-zero-disables-caching-immediately"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Setting a stage's method cache TTL to 0 is accepted and reflected immediately -- it is
    neither rejected nor silently coerced back to a non-zero default TTL."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
                          requestTemplates={"application/json": '{"statusCode": 200}'})
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
                                   responseTemplates={"application/json": '{"message": "ok"}'})

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = ctx.unique_name("sim2real-stage-")
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment["id"],
        cacheClusterEnabled=True,
        cacheClusterSize="0.5",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/*/*/caching/enabled", "value": "true"},
            {"op": "replace", "path": "/*/*/caching/ttlInSeconds", "value": "300"},
        ],
    )
    baseline = apigw.get_stage(restApiId=api_id, stageName=stage_name)["methodSettings"]["*/*"]
    assert baseline["cachingEnabled"] is True, f"expected caching enabled in baseline, got {baseline['cachingEnabled']!r}"
    assert baseline["cacheTtlInSeconds"] == 300, f"expected baseline TTL 300, got {baseline['cacheTtlInSeconds']!r}"

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/*/*/caching/ttlInSeconds", "value": "0"}],
    )
    updated = apigw.get_stage(restApiId=api_id, stageName=stage_name)["methodSettings"]["*/*"]

    assert updated["cachingEnabled"] is True, "caching must remain enabled, not implicitly disabled, when ttl is 0"
    assert updated["cacheTtlInSeconds"] == 0, (
        f"expected cacheTtlInSeconds to be 0 immediately after update, got {updated['cacheTtlInSeconds']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
