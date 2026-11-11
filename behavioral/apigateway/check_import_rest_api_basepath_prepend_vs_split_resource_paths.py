"""import-rest-api-basepath-prepend-vs-split-resource-paths."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "import-rest-api-basepath-prepend-vs-split-resource-paths"
GROUP = "representation"
SERVICES = ["apigateway"]


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so a throttle can
    be unrelated to the claim."""
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _doc(title):
    return {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "basePath": "/v1/api",
        "schemes": ["https"],
        "paths": {
            "/pets": {
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


def _import(ctx, apigw, basepath_mode, title):
    """Import the same document under one `basepath` mode; returns (api_id, paths)."""
    created = _retry_throttled(lambda: apigw.import_rest_api(
        body=json.dumps(_doc(title)).encode("utf-8"),
        parameters={"basepath": basepath_mode},
    ))
    api_id = created["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: apigw.delete_rest_api(restApiId=api_id)))
    resources = apigw.get_resources(restApiId=api_id)["items"]
    return api_id, {r["path"] for r in resources}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Importing the same /v1/api basePath document under basepath=prepend keeps the whole
    basePath on every resource path, while basepath=split keeps only its last segment.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-import-api-basePath.html
    """
    apigw = ctx.client("apigateway")

    prepend_title = ctx.unique_name("sim2real-behav-apigw-bp-prepend-")
    _, prepend_paths = _import(ctx, apigw, "prepend", prepend_title)
    expected_prepend = {"/", "/v1", "/v1/api", "/v1/api/pets"}
    assert prepend_paths == expected_prepend, (
        f"basepath=prepend must keep the whole basePath on the resource path: expected "
        f"{sorted(expected_prepend)!r}, got {sorted(prepend_paths)!r}"
    )

    split_title = ctx.unique_name("sim2real-behav-apigw-bp-split-")
    _, split_paths = _import(ctx, apigw, "split", split_title)
    expected_split = {"/", "/api", "/api/pets"}
    assert split_paths == expected_split, (
        f"basepath=split must keep only the basePath's last segment on the resource path: "
        f"expected {sorted(expected_split)!r}, got {sorted(split_paths)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
