"""deployment-created-date-timestamp-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deployment-created-date-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The createdDate timestamp returned inline by CreateDeployment must be the exact
    same instant (not rounded/truncated to a coarser unit by a separate read path) as
    the createdDate a subsequent GetDeployment call reports for the same deployment."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    created = apigw.create_deployment(restApiId=api_id)
    deployment_id = created["id"]
    ctx.on_cleanup(
        lambda: apigw.delete_deployment(restApiId=api_id, deploymentId=deployment_id)
    )
    created_ts = created["createdDate"]

    fetched = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    fetched_ts = fetched["createdDate"]

    assert created_ts == fetched_ts, (
        f"createdDate differs between CreateDeployment ({created_ts!r}) and "
        f"GetDeployment ({fetched_ts!r}) for the same deployment"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
