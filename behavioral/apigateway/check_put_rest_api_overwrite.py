"""put-rest-api-overwrite."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-rest-api-overwrite"
GROUP = 'rest-api'
SERVICES = ['apigateway']


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRestApis lists a new RestApi; PutRestApi in overwrite mode replaces the whole resource
    tree from the supplied OpenAPI document (a pre-existing resource is gone, only the document's
    path remains), and UpdateRestApi still works afterwards."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)

    # Paginate: GetRestApis caps a page at 25 items, so on an account carrying >25 RestApis the
    # just-created one may not land on the first page — walk all pages before asserting absence.
    apis = []
    for page in ag.get_paginator("get_rest_apis").paginate():
        apis.extend(page.get("items", []))
    assert any(a["id"] == api_id for a in apis), f"expected {api_id!r} in GetRestApis"

    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="preexisting")
    before_paths = {r["path"] for r in ag.get_resources(restApiId=api_id)["items"]}
    assert before_paths == {"/", "/preexisting"}, f"expected '/preexisting' to be created, got {before_paths!r}"

    overlay = {
        "openapi": "3.0.1",
        "info": {"title": "overlay", "version": "1.0"},
        "paths": {
            "/merged": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "mock",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }
    ag.put_rest_api(restApiId=api_id, mode="overwrite", body=json.dumps(overlay).encode("utf-8"))
    after_paths = {r["path"] for r in ag.get_resources(restApiId=api_id)["items"]}
    assert after_paths == {"/", "/merged"}, (
        f"expected PutRestApi(mode=overwrite) to replace the tree with just '/merged', "
        f"got {after_paths!r}"
    )

    ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "updated-desc"}],
    )
    updated = ag.get_rest_api(restApiId=api_id)
    assert updated.get("description") == "updated-desc", (
        f"expected UpdateRestApi to apply, got {updated!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
