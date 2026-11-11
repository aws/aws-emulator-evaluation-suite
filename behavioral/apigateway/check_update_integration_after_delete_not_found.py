"""update-integration-after-delete-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-integration-after-delete-not-found"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIntegration applies a patch to a live integration (positive control) and, once the
    integration is deleted, the identical patch fails with NotFoundException and does not
    recreate it."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")

    # positive control: the integration is live and the same patch succeeds against it
    updated = apigw.update_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/timeoutInMillis", "value": "5000"}],
    )
    assert updated["timeoutInMillis"] == 5000, f"expected patch to apply on the live integration, got {updated!r}"
    fetched = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["timeoutInMillis"] == 5000, f"expected persisted timeoutInMillis=5000, got {fetched!r}"

    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    err = _client_error(
        lambda: apigw.update_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            patchOperations=[{"op": "replace", "path": "/timeoutInMillis", "value": "6000"}],
        )
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Integration identifier specified", (
        f"expected the exact NotFound message, got {err.get('Message')!r}"
    )

    # confirm it really was not recreated by the failed update
    err = _client_error(lambda: apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET"))
    assert err.get("Code") == "NotFoundException", (
        f"expected NotFoundException after failed update, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "Invalid Integration identifier specified", (
        f"expected the exact NotFound message after failed update, got {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
