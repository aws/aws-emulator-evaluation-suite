"""put-rest-api-overwrite-and-merge-modes."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-rest-api-overwrite-and-merge-modes"
GROUP = "state-machine"
SERVICES = ["apigateway"]


def _mock_doc(title, path):
    return {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "paths": {
            path: {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRestApi with mode=overwrite replaces the entire resource tree from the supplied
    definition, while mode=merge only adds new paths on top of the existing tree; both are
    observable via GetResources."""
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-apigw-")
    api_id = apigw.create_rest_api(name=api_name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="foo")

    paths_after_create = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert paths_after_create == {"/", "/foo"}, (
        f"expected CreateResource to add /foo, got {paths_after_create}"
    )

    merge_doc = _mock_doc(api_name, "/bar")
    apigw.put_rest_api(restApiId=api_id, mode="merge", body=json.dumps(merge_doc).encode())

    paths_after_merge = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert paths_after_merge == {"/", "/foo", "/bar"}, (
        f"merge must keep /foo and add /bar, got {paths_after_merge}"
    )

    overwrite_doc = _mock_doc(api_name, "/baz")
    apigw.put_rest_api(restApiId=api_id, mode="overwrite", body=json.dumps(overwrite_doc).encode())

    paths_after_overwrite = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert paths_after_overwrite == {"/", "/baz"}, (
        f"overwrite must replace the entire tree, got {paths_after_overwrite}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
