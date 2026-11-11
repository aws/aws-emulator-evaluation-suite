"""concurrent-create-deployment-serializes-stage-update."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-deployment-serializes-stage-update"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment(stageName=...) and UpdateStage racing on the same stage's
    deploymentId are serialized: the stage always ends pointing at exactly one of
    the two candidate deployments, and every subsequent read agrees (no torn state).
    """
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-cd-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

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
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    deployment1_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = ctx.unique_name("sim2real-stage-")[:64]
    apigw.create_stage(
        restApiId=api_id, stageName=stage_name, deploymentId=deployment1_id
    )

    barrier = threading.Barrier(2)
    results: dict[str, object] = {}

    def _create_deployment() -> None:
        barrier.wait(timeout=5)
        try:
            resp = apigw.create_deployment(restApiId=api_id, stageName=stage_name)
            results["new_deployment_id"] = resp["id"]
        except ClientError as err:
            results["create_deployment_error"] = _error_code(err)

    def _update_stage() -> None:
        barrier.wait(timeout=5)
        try:
            apigw.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[
                    {"op": "replace", "path": "/deploymentId", "value": deployment1_id}
                ],
            )
        except ClientError as err:
            results["update_stage_error"] = _error_code(err)
            results["update_stage_message"] = err.response.get("Error", {}).get("Message")

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_create_deployment)
        f2 = pool.submit(_update_stage)
        f1.result(timeout=30)
        f2.result(timeout=30)

    # Both racers legitimately reaching a terminal state (success, or one rejected
    # with ConflictException) is fine; what must NEVER happen is a torn/partial stage.
    create_deployment_failed = "create_deployment_error" in results
    update_stage_failed = "update_stage_error" in results
    if create_deployment_failed:
        assert results["create_deployment_error"] == "ConflictException", (
            f"CreateDeployment raced and failed with an unexpected code: "
            f"{results['create_deployment_error']}"
        )
    if update_stage_failed:
        assert results["update_stage_error"] == "ConflictException", (
            f"UpdateStage raced and failed with an unexpected code: "
            f"{results['update_stage_error']}"
        )
        assert results["update_stage_message"] == (
            "Unable to complete operation due to concurrent modification. Please try again later."
        ), f"unexpected UpdateStage ConflictException message {results['update_stage_message']!r}"
    assert not (create_deployment_failed and update_stage_failed), (
        "both racers were rejected -- expected at least one to win"
    )

    candidates = {deployment1_id}
    if not create_deployment_failed:
        candidates.add(results["new_deployment_id"])

    # Poll GetStage repeatedly: every read must agree on a single, valid deploymentId.
    observed = set()
    for _ in range(6):
        stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
        observed.add(stage["deploymentId"])
        time.sleep(0.5)

    assert len(observed) == 1, f"stage deploymentId was not stable across reads: {observed}"
    final_deployment_id = next(iter(observed))
    assert final_deployment_id in candidates, (
        f"final deploymentId {final_deployment_id} was not one of the racers' candidate "
        f"deployments {candidates} -- torn/partial state"
    )
    # The winning deployment must actually exist (not a corrupted reference).
    apigw.get_deployment(restApiId=api_id, deploymentId=final_deployment_id)


def _error_code(err: Exception) -> str | None:
    response = getattr(err, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
