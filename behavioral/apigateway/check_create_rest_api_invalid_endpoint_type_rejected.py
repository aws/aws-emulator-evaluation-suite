"""create-rest-api-invalid-endpoint-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rest-api-invalid-endpoint-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRestApi with an unsupported endpointConfiguration.types value is rejected."""
    apigw = ctx.client("apigateway")
    bad_name = ctx.unique_name("sim2real-behav-apigw-bad-")

    code, message = _error(
        lambda: apigw.create_rest_api(
            name=bad_name,
            endpointConfiguration={"types": ["NOT_A_REAL_ENDPOINT_TYPE"]},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value '[NOT_A_REAL_ENDPOINT_TYPE]' at "
        "'createRestApiInput.endpointConfiguration.types' failed to satisfy constraint: "
        "Member must satisfy constraint: [Member must satisfy enum value set: "
        "[PRIVATE, EDGE, REGIONAL]]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: no REST API with that name was created.
    matches = [api for api in _list_all_rest_apis(apigw) if api["name"] == bad_name]
    assert matches == [], "a REST API was created despite the rejected request"

    # (c) positive control: a valid endpointConfiguration.types succeeds.
    good_name = ctx.unique_name("sim2real-behav-apigw-good-")
    created = apigw.create_rest_api(name=good_name, endpointConfiguration={"types": ["REGIONAL"]})
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=created["id"]))

    # Independent read at the destination, not the create call's own response.
    fetched = apigw.get_rest_api(restApiId=created["id"])
    assert fetched["endpointConfiguration"]["types"] == ["REGIONAL"], (
        f"expected endpointConfiguration.types == ['REGIONAL'], "
        f"got {fetched.get('endpointConfiguration')!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _list_all_rest_apis(apigw):
    items = []
    resp = apigw.get_rest_apis(limit=500)
    items.extend(resp.get("items", []))
    while resp.get("position"):
        resp = apigw.get_rest_apis(limit=500, position=resp["position"])
        items.extend(resp.get("items", []))
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
