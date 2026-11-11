"""get-deployments-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-deployments-ordering"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDeployments lists every deployment of the API exactly once with its description, and
    their createdDate values follow the order the deployments were created in."""
    apig = ctx.client("apigateway")
    rest_api_id = apig.create_rest_api(
        name=ctx.unique_name("sim2real-behav-deployorder-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=rest_api_id))
    _add_root_mock_method(apig, rest_api_id)

    created_ids: list[str] = []
    for i in range(3):
        dep = apig.create_deployment(restApiId=rest_api_id, description=f"sim2real-dep-{i}")
        created_ids.append(dep["id"])
        # createdDate has 1-second resolution server-side; separate calls to force distinct
        # timestamps.
        time.sleep(1.2)

    # The list order itself is not documented, so the order is read from createdDate.
    listed = apig.get_deployments(restApiId=rest_api_id)["items"]
    assert sorted(item["id"] for item in listed) == sorted(created_ids), (
        f"GetDeployments listed {[item['id'] for item in listed]}, expected each of "
        f"{sorted(created_ids)} once"
    )
    items = {item["id"]: item for item in listed}
    descriptions = [items[d].get("description") for d in created_ids]
    assert descriptions == [f"sim2real-dep-{i}" for i in range(3)], (
        f"GetDeployments descriptions in creation order are {descriptions}"
    )
    created = [items[d]["createdDate"] for d in created_ids]
    assert created == sorted(created) and len(set(created)) == 3, (
        f"createdDate in creation order is {created}; deployments created 1.2s apart carry "
        f"strictly increasing createdDate values"
    )


def _add_root_mock_method(apig, rest_api_id: str) -> None:
    """Wire up a trivial GET / MOCK method so the API has something deployable."""
    root_id = next(r["id"] for r in apig.get_resources(restApiId=rest_api_id)["items"] if r["path"] == "/")
    apig.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apig.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apig.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apig.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
