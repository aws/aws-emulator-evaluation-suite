"""update-method-not-found-error-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-method-not-found-error-contract"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMethod on a method deleted out-of-band returns NotFoundException, not ConflictException."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )

    # Positive control: the identical patch succeeds while the method still exists, so a
    # later rejection is attributable to the method being gone, not to a malformed request.
    control = apigw.update_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/apiKeyRequired", "value": "true"}],
    )
    assert control["apiKeyRequired"] is True, (
        f"positive control did not take effect, got apiKeyRequired={control.get('apiKeyRequired')!r}"
    )

    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    # Independent read: the deletion is visible through a different operation than the one
    # that mutated, before we ever attempt the update that is under test.
    read_err = _client_error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert read_err.get("Code") == "NotFoundException", (
        f"expected the deleted method to read back NotFoundException, got {read_err.get('Code')!r}"
    )
    assert read_err.get("Message") == "Invalid Method identifier specified", (
        f"expected the exact NotFound message reading the deleted method, got {read_err.get('Message')!r}"
    )

    update_err = _client_error(
        lambda: apigw.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            patchOperations=[{"op": "replace", "path": "/apiKeyRequired", "value": "false"}],
        )
    )
    update_code = update_err.get("Code")
    assert update_code == "NotFoundException", (
        f"expected NotFoundException, got {update_code!r}"
    )
    assert update_code != "ConflictException", (
        f"UpdateMethod on a deleted method must not surface as ConflictException, got {update_code!r}"
    )
    assert update_err.get("Message") == "Invalid Method identifier specified", (
        f"expected the exact NotFound message updating the deleted method, got {update_err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
