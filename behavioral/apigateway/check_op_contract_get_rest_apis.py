"""op-contract-getRestApis."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getRestApis"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRestApis lists a created API by id/name; an invalid pagination position token -> BadRequestException."""
    apigw = ctx.client("apigateway")

    name = ctx.unique_name("sim2real-apigw-")
    api_id = apigw.create_rest_api(
        name=name, description="sim2real getRestApis check", tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    listing = apigw.get_rest_apis(limit=500)
    matches = [item for item in listing["items"] if item["id"] == api_id]
    assert len(matches) == 1, f"created API not found (exactly once) in GetRestApis listing: {matches}"
    assert matches[0]["name"] == name, f"expected name {name!r}, got {matches[0]['name']!r}"
    assert matches[0]["description"] == "sim2real getRestApis check", (
        f"expected description 'sim2real getRestApis check', got {matches[0]['description']!r}"
    )

    # limit enforces the page size; at least one API (the one just created) exists, so a
    # limit of 1 must return exactly one item, never zero and never more than the limit.
    limited = apigw.get_rest_apis(limit=1)
    assert len(limited["items"]) == 1, f"expected exactly 1 item with limit=1, got {limited['items']}"

    code, message = _error(lambda: apigw.get_rest_apis(position="not-a-real-pagination-token"))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        'Invalid position parameter'
    ), f"unexpected {code} message: {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
