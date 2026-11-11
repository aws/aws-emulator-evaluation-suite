"""concurrent-delete-and-update-stage-serializes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-delete-and-update-stage-serializes"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStage racing DeleteStage on one stage: the stage ends deleted, and UpdateStage either succeeds
    (landing first) or fails with NotFoundException, never any other error."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-stagerace-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
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

    stage_name = "sim"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    def _updater():
        try:
            apigw.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real-updated"}],
            )
            return ("ok", None, None)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    def _deleter():
        try:
            apigw.delete_stage(restApiId=api_id, stageName=stage_name)
            return ("ok", None)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        update_future = pool.submit(_updater)
        delete_future = pool.submit(_deleter)
        update_outcome = update_future.result()
        delete_outcome = delete_future.result()

    assert delete_outcome[0] == "ok", f"DeleteStage should unconditionally succeed, got {delete_outcome}"
    assert update_outcome[0] == "ok" or update_outcome[1] == "NotFoundException", (
        f"UpdateStage must succeed or fail with NotFoundException, got {update_outcome}"
    )
    if update_outcome[0] == "err":
        assert update_outcome[2] == "Invalid stage identifier specified", (
            f"unexpected UpdateStage not-found message {update_outcome[2]!r}"
        )

    final_code, message = _error(lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name))
    assert final_code == "NotFoundException", (
        f"expected stage to be gone after the race, got error code {final_code!r}"
    )
    assert message == "Invalid stage identifier specified", f"unexpected message {message!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
