"""op-contract-createRestApi."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createRestApi"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRestApi echoes name/description/endpointConfiguration and allocates a root resource on
    success; a negative minimumCompressionSize is rejected with BadRequestException so no API is
    ever created for it."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-")

    created = apigw.create_rest_api(
        name=name,
        description="behavioral fidelity check",
        endpointConfiguration={"types": ["REGIONAL"]},
        minimumCompressionSize=0,
        tags={"sim2real": "op-contract-createRestApi"},
    )
    api_id = created["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=api_id)))
    assert created["name"] == name
    assert created["description"] == "behavioral fidelity check"
    assert created["endpointConfiguration"]["types"] == ["REGIONAL"]
    assert created["minimumCompressionSize"] == 0

    resources = apigw.get_resources(restApiId=api_id)["items"]
    assert len(resources) == 1 and resources[0]["path"] == "/"
    assert resources[0]["id"] == created["rootResourceId"]

    bad_name = ctx.unique_name("sim2real-behav-bad-")
    err = _client_error(
        lambda: apigw.create_rest_api(name=bad_name, minimumCompressionSize=-1)
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid minimum compression size, must be between 0 and 10485760", (
        f"expected the exact compression-size message, got {err.get('Message')!r}"
    )

    all_names = {api["name"] for api in _paginated_rest_apis(apigw)}
    assert bad_name not in all_names, "an API was created despite the invalid request"


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


def _paginated_rest_apis(apigw, max_pages=10):
    items = []
    position = None
    for _ in range(max_pages):
        kwargs = {"limit": 500}
        if position:
            kwargs["position"] = position
        page = apigw.get_rest_apis(**kwargs)
        items.extend(page.get("items", []))
        position = page.get("position")
        if not position:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
