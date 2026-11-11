"""op-contract-deleteMethod."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deleteMethod"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMethod removes the method so GetMethod subsequently 404s; deleting an httpMethod that
    was never defined on the resource is rejected with NotFoundException."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")

    fetched = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["httpMethod"] == "GET", f"expected the just-created GET method, got {fetched['httpMethod']!r}"

    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    err = _client_error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert err.get("Code") == "NotFoundException", f"method still present after delete, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Method identifier specified", (
        f"expected the exact NotFound message from GetMethod, got {err.get('Message')!r}"
    )

    err = _client_error(
        lambda: apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException for never-created method, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Method identifier specified", (
        f"expected the exact NotFound message from DeleteMethod, got {err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real-check": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
