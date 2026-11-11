"""import-rest-api-builds-full-resource-tree."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-rest-api-builds-full-resource-tree"
GROUP = 'rest-api'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _minimal_openapi_body_multi(title, paths):
    """Minimal OpenAPI 3.0 doc with MOCK-integrated methods; `paths` maps a URL path to a list of
    lowercase HTTP verbs."""
    doc_paths = {}
    for path, verbs in paths.items():
        ops = {}
        for verb in verbs:
            ops[verb] = {
                "responses": {"200": {"description": "ok"}},
                "x-amazon-apigateway-integration": {
                    "type": "mock",
                    "requestTemplates": {"application/json": '{"statusCode": 200}'},
                    "responses": {
                        "default": {
                            "statusCode": "200",
                            "responseTemplates": {"application/json": '{"message": "ok"}'},
                        }
                    },
                },
            }
        doc_paths[path] = ops
    doc = {"openapi": "3.0.1", "info": {"title": title, "version": "1.0"}, "paths": doc_paths}
    return json.dumps(doc).encode("utf-8")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportRestApi builds the resource tree from an OpenAPI spec: each path is a root child with
    the right pathPart, defined methods keep their MOCK integration, undefined ones are NotFound."""
    ag = ctx.client("apigateway")
    title = ctx.unique_name("sim2real-behav-import-api-")
    body = _minimal_openapi_body_multi(title, {"/orders": ["get"], "/items": ["post"]})
    imported = ag.import_rest_api(body=body)
    api_id = imported["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    ag.tag_resource(
        resourceArn=f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}",
        tags={"sim2real": "import-rest-api-builds-full-resource-tree"},
    )
    assert imported["name"] == title, f"expected imported RestApi name to match the spec title, got {imported!r}"

    resources = ag.get_resources(restApiId=api_id)["items"]
    by_path = {r["path"]: r for r in resources}
    assert "/orders" in by_path, f"expected ImportRestApi to materialize '/orders', got paths={list(by_path)!r}"
    assert "/items" in by_path, f"expected ImportRestApi to materialize '/items', got paths={list(by_path)!r}"

    root = by_path["/"]
    orders = by_path["/orders"]
    items = by_path["/items"]
    assert orders["parentId"] == root["id"], "expected '/orders' to be a direct child of the root resource"
    assert items["parentId"] == root["id"], "expected '/items' to be a direct child of the root resource"
    assert orders["pathPart"] == "orders", f"expected pathPart 'orders', got {orders['pathPart']!r}"
    assert items["pathPart"] == "items", f"expected pathPart 'items', got {items['pathPart']!r}"

    orders_method = ag.get_method(restApiId=api_id, resourceId=orders["id"], httpMethod="GET")
    assert orders_method["httpMethod"] == "GET", (
        f"expected GetMethod on the imported /orders GET to report httpMethod='GET', got {orders_method['httpMethod']!r}"
    )
    assert "MOCK" == ag.get_integration(
        restApiId=api_id, resourceId=orders["id"], httpMethod="GET"
    )["type"], "expected the imported GET /orders method to keep its MOCK integration from the spec"

    items_method = ag.get_method(restApiId=api_id, resourceId=items["id"], httpMethod="POST")
    assert items_method["httpMethod"] == "POST", (
        f"expected GetMethod on the imported /items POST to report httpMethod='POST', got {items_method['httpMethod']!r}"
    )

    missing_code, missing_message = _error(
        lambda: ag.get_method(restApiId=api_id, resourceId=items["id"], httpMethod="GET")
    )
    assert missing_code == "NotFoundException", (
        f"expected NotFoundException for a method never defined in the imported spec, got {missing_code}"
    )
    assert missing_message == "Invalid Method identifier specified", (
        f"unexpected message {missing_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
