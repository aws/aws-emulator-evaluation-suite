"""rest-api-binary-media-types-special-chars-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rest-api-binary-media-types-special-chars-preserved"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """binaryMediaTypes entries containing slashes, wildcards, and parameterized
    media-type syntax must be returned byte-for-byte unmodified by GetRestApi -- no
    '~1' path-escaping (that only applies to JSON-Patch paths) and no reordering."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    binary_media_types = [
        "application/vnd.api+json",
        "image/*",
        "application/octet-stream;charset=binary",
        "multipart/form-data;boundary=----Sim2RealBoundary123",
    ]

    created = apigw.create_rest_api(
        name=name, binaryMediaTypes=binary_media_types, tags={"sim2real": name}
    )
    api_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    assert created["binaryMediaTypes"] == binary_media_types, (
        f"CreateRestApi response mutated binaryMediaTypes: {created['binaryMediaTypes']!r}"
    )

    fetched = apigw.get_rest_api(restApiId=api_id)
    assert fetched["binaryMediaTypes"] == binary_media_types, (
        f"GetRestApi mutated binaryMediaTypes: sent={binary_media_types!r} got={fetched['binaryMediaTypes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
