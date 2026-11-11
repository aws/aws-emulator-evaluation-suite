"""deployment-update-description-and-list."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deployment-update-description-and-list"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeployment patches one deployment's description, leaves a sibling deployment
    untouched, and GetDeployments reflects both outcomes."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-deploy-")
    rest_api_id = apigw.create_rest_api(name=name, tags={"sim2real-check": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    created = apigw.create_deployment(restApiId=rest_api_id, description="initial deployment")
    deployment_id = created["id"]
    assert created["description"] == "initial deployment", (
        f"expected 'initial deployment', got {created['description']!r}"
    )

    other = apigw.create_deployment(restApiId=rest_api_id, description="untouched deployment")
    other_id = other["id"]
    assert other_id != deployment_id, "the two deployments must have distinct ids"

    updated = apigw.update_deployment(
        restApiId=rest_api_id,
        deploymentId=deployment_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "updated deployment"}],
    )
    assert updated["id"] == deployment_id, f"expected id {deployment_id!r}, got {updated['id']!r}"
    assert updated["description"] == "updated deployment", (
        f"expected 'updated deployment', got {updated['description']!r}"
    )

    listed = apigw.get_deployments(restApiId=rest_api_id)["items"]
    by_id = {d["id"]: d for d in listed}
    match = by_id.get(deployment_id)
    assert match is not None, "the deployment must appear in the GetDeployments listing"
    assert match["description"] == "updated deployment", (
        f"expected 'updated deployment', got {match['description']!r}"
    )

    sibling = by_id.get(other_id)
    assert sibling is not None, "the untouched deployment must still appear in the listing"
    assert sibling["description"] == "untouched deployment", (
        f"patching one deployment must not affect another; got {sibling['description']!r}"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
