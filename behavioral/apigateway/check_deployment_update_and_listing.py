"""deployment-update-and-listing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-update-and-listing"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Multiple deployments are created, listed, individually retrievable/patchable/deletable."""
    apigw = ctx.client("apigateway")
    api_id, _root_id = _create_deployable_api(ctx)

    dep1 = apigw.create_deployment(restApiId=api_id, description="deployment-one")
    dep1_id = dep1["id"]
    assert dep1["description"] == "deployment-one", dep1

    dep2 = apigw.create_deployment(restApiId=api_id, description="deployment-two")
    dep2_id = dep2["id"]
    assert dep2["description"] == "deployment-two", dep2
    assert dep2_id != dep1_id, f"expected distinct deployment ids, got {dep1_id!r} twice"

    listed_ids = {d["id"] for d in apigw.get_deployments(restApiId=api_id)["items"]}
    assert dep1_id in listed_ids and dep2_id in listed_ids, (
        f"both deployments should be listed, got {listed_ids}"
    )

    got1 = apigw.get_deployment(restApiId=api_id, deploymentId=dep1_id)
    assert got1["description"] == "deployment-one", got1

    updated = apigw.update_deployment(
        restApiId=api_id, deploymentId=dep1_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "deployment-one-updated"}],
    )
    assert updated["description"] == "deployment-one-updated", updated

    refetched = apigw.get_deployment(restApiId=api_id, deploymentId=dep1_id)
    assert refetched["description"] == "deployment-one-updated", refetched

    apigw.delete_deployment(restApiId=api_id, deploymentId=dep2_id)

    not_found = ("NotFoundException", "Invalid Deployment identifier specified")
    err = _error(lambda: apigw.get_deployment(restApiId=api_id, deploymentId=dep2_id))
    assert err == not_found, f"expected {not_found!r} reading a deleted deployment, got {err!r}"

    err = _error(lambda: apigw.update_deployment(
        restApiId=api_id, deploymentId=dep2_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "should-not-apply"}],
    ))
    assert err == not_found, f"expected {not_found!r} mutating a deleted deployment, got {err!r}"

    remaining_ids = {d["id"] for d in apigw.get_deployments(restApiId=api_id)["items"]}
    assert dep1_id in remaining_ids and dep2_id not in remaining_ids, (
        f"expected {dep1_id} present and {dep2_id} absent, got {remaining_ids}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_deployable_api(ctx):
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": "true"}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": ""},
    )
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
