"""update-method-nonexistent-method-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-method-nonexistent-method-not-found"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The same UpdateMethod patch succeeds on a live method, fails with NotFoundException once
    DeleteMethod removed it (GetMethod agrees), and succeeds again after the method is recreated
    under the same key."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-bhv-api-"),
        tags={"sim2real": "update-method-nonexistent-method-not-found"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    patch = [{"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"}]

    def update() -> dict[str, Any]:
        return apigw.update_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", patchOperations=patch)

    # Positive control: the identical patch succeeds while the method is live.
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    updated = update()
    assert updated["authorizationType"] == "AWS_IAM", (
        f"positive control did not apply, got {updated['authorizationType']!r}"
    )
    confirmed = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert confirmed["authorizationType"] == "AWS_IAM", (
        f"expected the positive control to be visible on read, got {confirmed['authorizationType']!r}"
    )

    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    err = _client_error(update)
    assert err.get("Code") == "NotFoundException", (
        f"expected NotFoundException on a deleted method, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "Invalid Method identifier specified", (
        f"expected the exact NotFound message on a deleted method, got {err.get('Message')!r}"
    )

    # Independent read: the method is gone, not merely un-updatable.
    get_err = _client_error(lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET"))
    assert get_err.get("Code") == "NotFoundException", (
        f"expected NotFoundException reading a deleted method, got {get_err.get('Code')!r}"
    )
    assert get_err.get("Message") == "Invalid Method identifier specified", (
        f"expected the exact NotFound message reading a deleted method, got {get_err.get('Message')!r}"
    )

    # Restore: recreating the method under the same resourceId/httpMethod key makes the
    # identical UpdateMethod call succeed again.
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    restored = update()
    assert restored["authorizationType"] == "AWS_IAM", (
        f"expected UpdateMethod to succeed again after recreation, got {restored['authorizationType']!r}"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses is the strongest signal available and must not be
    reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
