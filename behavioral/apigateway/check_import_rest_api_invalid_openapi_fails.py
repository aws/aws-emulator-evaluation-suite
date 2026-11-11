"""import-rest-api-invalid-openapi-fails."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "import-rest-api-invalid-openapi-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportRestApi imports a well-formed OpenAPI document (positive control) and rejects a
    malformed one with BadRequestException, leaving no partially populated RestApi behind."""
    apigw = ctx.client("apigateway")

    title = ctx.unique_name("sim2real-behav-apigw-import-invalid-")
    valid_document = json.dumps({
        "openapi": "3.0.1",
        "info": {"title": title, "version": "1.0"},
        "paths": {},
    }).encode()
    imported = apigw.import_rest_api(body=valid_document)
    api_id = imported["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    assert imported.get("name") == title, (
        f"positive control: expected the imported API to be named {title!r}, got "
        f"{imported.get('name')!r}"
    )
    baseline_ids = {a["id"] for a in _list_all_rest_apis(apigw)}
    assert api_id in baseline_ids, (
        f"positive control: {api_id!r} did not appear in get_rest_apis after a valid import"
    )

    malformed_body = b'{"swagger": "2.0", "info": {"title": "broken" '  # truncated / invalid JSON

    code, message = _error(lambda: apigw.import_rest_api(body=malformed_body))
    assert code == "BadRequestException", (
        f"expected BadRequestException importing a malformed OpenAPI document, got {code!r}"
    )
    assert message == "Invalid OpenAPI input.", f"unexpected rejection message {message!r}"

    after_ids = {a["id"] for a in _list_all_rest_apis(apigw)}
    new_ids = after_ids - baseline_ids
    assert not new_ids, f"ImportRestApi left behind partially-created API(s): {new_ids}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised.

    Raises on unexpected SUCCESS rather than returning a falsy sentinel: a call real
    AWS accepted is the strongest possible signal, and returning None here would
    report it as a code mismatch that reads like a naming difference."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be REJECTED but it succeeded, returning {result!r}"
    )


def _list_all_rest_apis(apigw) -> list[dict]:
    items: list[dict] = []
    position = None
    while True:
        kwargs = {"limit": 500}
        if position:
            kwargs["position"] = position
        resp = apigw.get_rest_apis(**kwargs)
        items.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
