"""rest-api-put-overwrite-and-import."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rest-api-put-overwrite-and-import"
GROUP = "state-machine"
SERVICES = ["apigateway"]


def _swagger_with_path(path_part: str, title: str) -> bytes:
    spec = {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "basePath": "/",
        "schemes": ["https"],
        "paths": {
            f"/{path_part}": {
                "get": {
                    "responses": {"200": {"description": "OK"}},
                    "x-amazon-apigateway-integration": {
                        "type": "mock",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }
    return json.dumps(spec).encode("utf-8")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportRestApi bootstraps an API; PutRestApi mode=overwrite replaces its resource tree wholesale."""
    apigw = ctx.client("apigateway")
    title = ctx.unique_name("sim2real-behav-import-")

    imported = apigw.import_rest_api(body=_swagger_with_path("pets", title))
    api_id = imported["id"]
    assert imported["name"] == title, f"expected ImportRestApi to name the API {title!r}, got {imported!r}"
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    paths_after_import = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert "/pets" in paths_after_import, f"expected ImportRestApi to build /pets, got {paths_after_import}"
    assert "/items" not in paths_after_import, f"unexpected /items before any overwrite, got {paths_after_import}"
    assert paths_after_import == {"/", "/pets"}, (
        f"expected ImportRestApi to build the resource tree from the swagger doc exactly, got {paths_after_import}"
    )

    overwritten = apigw.put_rest_api(
        restApiId=api_id, mode="overwrite", body=_swagger_with_path("items", title)
    )
    assert overwritten["id"] == api_id, f"expected PutRestApi to keep the same restApiId, got {overwritten!r}"

    paths_after_overwrite = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert "/items" in paths_after_overwrite, f"overwrite should introduce the new path, got {paths_after_overwrite}"
    assert "/pets" not in paths_after_overwrite, (
        f"overwrite should wholesale-replace the old resource tree, got {paths_after_overwrite}"
    )
    assert paths_after_overwrite == {"/", "/items"}, (
        f"overwrite should leave exactly the new tree with no stray resources, got {paths_after_overwrite}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
