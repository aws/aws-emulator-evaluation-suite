"""import-documentation-parts-malformed-body-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-documentation-parts-malformed-body-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts rejects a malformed JSON body with BadRequestException and creates
    nothing, while the same call with a well-formed body succeeds (positive control)."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-docimport-bad-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    baseline = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert baseline == [], "fresh API should start with no documentation parts"

    malformed_body = b'{"documentationParts": [ { "location": {"type": "API"} '  # truncated / invalid JSON

    code, message = _error(
        lambda: apigw.import_documentation_parts(
            restApiId=api_id, mode="merge", failOnWarnings=True, body=malformed_body
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Unable to build importer with provided input.", f"unexpected message {message!r}"

    after_malformed = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert after_malformed == [], (
        f"malformed import must not create any documentation parts, found {after_malformed}"
    )

    # Positive control: the same call with a well-formed body succeeds.
    valid_payload = {
        "swagger": "2.0",
        "info": {"title": ctx.unique_name("sim2real-docimport-valid-"), "version": "1.0"},
        "paths": {},
        "x-amazon-apigateway-documentation": {
            "version": "1.0",
            "documentationParts": [
                {"location": {"type": "API"}, "properties": {"description": "positive control"}},
            ],
        },
    }
    valid_body = json.dumps(valid_payload).encode("utf-8")
    result = apigw.import_documentation_parts(
        restApiId=api_id, mode="merge", failOnWarnings=True, body=valid_body
    )
    imported_ids = result["ids"]
    assert len(imported_ids) == 1, (
        f"positive control import should create exactly 1 documentation part, got {imported_ids!r}"
    )

    after_valid = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert {p["id"] for p in after_valid} == set(imported_ids), (
        f"positive control part not visible via independent GetDocumentationParts read: "
        f"{after_valid!r}"
    )


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected BadRequestException, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
