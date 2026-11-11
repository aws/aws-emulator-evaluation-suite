"""import-documentation-parts-invalid-format-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-documentation-parts-invalid-format-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts succeeds for a well-formed payload (positive control) and fails a
    malformed one wholesale with BadRequestException, creating no documentation part."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-docimport-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    good_payload = {
        "swagger": "2.0",
        "info": {"title": ctx.unique_name("sim2real-docimport-good-"), "version": "1.0"},
        "paths": {},
        "x-amazon-apigateway-documentation": {
            "version": "1.0",
            "documentationParts": [
                {"location": {"type": "API"}, "properties": {"description": "positive control"}},
            ],
        },
    }
    good_ids = apigw.import_documentation_parts(
        restApiId=api_id, mode="merge", body=json.dumps(good_payload).encode("utf-8")
    )["ids"]
    assert len(good_ids) == 1, (
        f"positive control: expected 1 documentation part imported from a well-formed "
        f"payload, got {good_ids!r}"
    )
    baseline_ids = {p["id"] for p in apigw.get_documentation_parts(restApiId=api_id).get("items", [])}
    assert baseline_ids == set(good_ids), (
        f"expected the positive-control part {good_ids!r} visible via GetDocumentationParts, "
        f"found {baseline_ids!r}"
    )

    bad_body = b"{not valid json or openapi at all {{{"
    code, message = _error(
        lambda: apigw.import_documentation_parts(restApiId=api_id, body=bad_body)
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException importing a malformed documentation payload, got {code!r}"
    )
    assert message == "Unable to build importer with provided input.", (
        f"unexpected rejection message {message!r}"
    )

    after_ids = {p["id"] for p in apigw.get_documentation_parts(restApiId=api_id).get("items", [])}
    assert after_ids == baseline_ids, (
        f"a rejected import must not add or remove documentation parts: "
        f"before={baseline_ids!r} after={after_ids!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
