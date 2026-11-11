"""put-rest-api-malformed-body-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-rest-api-malformed-body-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRestApi with a malformed OpenAPI/Swagger body must be rejected with BadRequestException,
    without disturbing a definition already applied by a prior, valid overwrite."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    # positive control: a well-formed overwrite on this same API must succeed, so a later
    # rejection is attributable to the malformed body and not to PutRestApi being broken outright.
    valid_body = json.dumps(
        {
            "swagger": "2.0",
            "info": {"title": "sim2real-valid", "version": "1.0"},
            "paths": {"/valid": {"get": {"responses": {"200": {"description": "ok"}}}}},
        }
    ).encode("utf-8")
    apigw.put_rest_api(restApiId=api_id, mode="overwrite", body=valid_body)
    valid_paths = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert valid_paths == {"/", "/valid"}, f"expected the valid overwrite to apply, got {valid_paths}"

    malformed_body = b'{"this-is": "not a valid swagger or openapi document at all"}'

    code, message = _error(lambda: apigw.put_rest_api(restApiId=api_id, mode="overwrite", body=malformed_body))
    assert code == "BadRequestException", f"expected BadRequestException for malformed body, got {code}"
    assert message == "Unable to determine OAS/Swagger version", f"unexpected message: {message!r}"

    # the rejected overwrite must leave the definition applied by the positive control untouched.
    resources_after = {r["path"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert resources_after == {"/", "/valid"}, (
        f"expected the rejected malformed overwrite to leave the prior definition intact, got {resources_after}"
    )


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
