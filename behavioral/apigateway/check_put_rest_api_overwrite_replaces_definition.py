"""put-rest-api-overwrite-replaces-definition."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rest-api-overwrite-replaces-definition"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRestApi in overwrite mode replaces the existing API's resource tree entirely."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-overwrite-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    orig = apigw.create_resource(
        restApiId=api_id, parentId=apigw.get_resources(restApiId=api_id)["items"][0]["id"], pathPart="orig"
    )
    apigw.put_method(restApiId=api_id, resourceId=orig["id"], httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=orig["id"], httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    before_paths = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert "/orig" in before_paths, before_paths

    overwrite_doc = {
        "swagger": "2.0",
        "info": {"title": "sim2real-overwritten", "version": "1.0"},
        "basePath": "/",
        "schemes": ["https"],
        "paths": {
            "/replaced": {
                "get": {
                    "responses": {"200": {"description": "OK"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }

    apigw.put_rest_api(restApiId=api_id, mode="overwrite", body=json.dumps(overwrite_doc).encode("utf-8"))

    after_resources = apigw.get_resources(restApiId=api_id)["items"]
    after_paths = {r["path"] for r in after_resources}
    assert after_paths == {"/", "/replaced"}, after_paths

    replaced = next(r for r in after_resources if r["path"] == "/replaced")
    assert "GET" in replaced.get("resourceMethods", {}), replaced

    replaced_integration = apigw.get_integration(restApiId=api_id, resourceId=replaced["id"], httpMethod="GET")
    assert replaced_integration.get("type") == "MOCK", replaced_integration

    orig_still_listed = any(r["id"] == orig["id"] for r in after_resources)
    assert not orig_still_listed, after_resources

    try:
        apigw.get_method(restApiId=api_id, resourceId=orig["id"], httpMethod="GET")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "NotFoundException", e.response
        assert e.response["Error"]["Message"] == "Invalid Resource identifier specified", e.response
    else:
        raise AssertionError(
            "expected GetMethod on the resource dropped by overwrite to fail with NotFoundException"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
