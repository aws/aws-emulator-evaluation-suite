"""rest-api-binary-media-types-list-order-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rest-api-binary-media-types-list-order-preserved"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """binaryMediaTypes order and values survive CreateRestApi and a subsequent UpdateRestApi append."""
    apigw = ctx.client("apigateway")

    initial_types = ["image/png", "application/octet-stream", "video/x-msvideo"]
    created = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-binmedia-"),
        binaryMediaTypes=initial_types,
        tags={"sim2real": CHECK},
    )
    rest_api_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    assert created["binaryMediaTypes"] == initial_types, (
        f"CreateRestApi response order/values changed: {created['binaryMediaTypes']!r}"
    )

    fetched = apigw.get_rest_api(restApiId=rest_api_id)
    assert fetched["binaryMediaTypes"] == initial_types, (
        f"GetRestApi order/values changed: {fetched['binaryMediaTypes']!r} != {initial_types!r}"
    )

    apigw.update_rest_api(
        restApiId=rest_api_id,
        patchOperations=[
            {"op": "add", "path": "/binaryMediaTypes/video~1mp4", "value": ""}
        ],
    )

    expected_after_update = initial_types + ["video/mp4"]
    fetched_after = apigw.get_rest_api(restApiId=rest_api_id)
    assert fetched_after["binaryMediaTypes"] == expected_after_update, (
        f"binaryMediaTypes after append changed order/values: "
        f"{fetched_after['binaryMediaTypes']!r} != {expected_after_update!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
