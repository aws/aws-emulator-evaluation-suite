"""import-documentation-parts-invalid-mode-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-documentation-parts-invalid-mode-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]

_THROTTLE = ("TooManyRequestsException", "Too Many Requests")


def _doc_body(description: str) -> bytes:
    doc = {
        "swagger": "2.0",
        "info": {"title": "doc-import", "version": "1"},
        "paths": {},
        "x-amazon-apigateway-documentation": {
            "documentationParts": [{"location": {"type": "API"}, "properties": {"description": description}}]
        },
    }
    return json.dumps(doc).encode("utf-8")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _import_with_backoff(fn, *, budget_s: float = 60.0):
    """Retry fn() across ImportDocumentationParts' own account-level throttle."""
    deadline = time.monotonic() + budget_s
    delay = 2.0
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"], err.get("Message")) != _THROTTLE or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 10.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts rejects a mode value outside merge/overwrite and creates
    nothing; the same call with a valid mode (positive control) commits the part."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-docimport-mode-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    before_ids = {p["id"] for p in apigw.get_documentation_parts(restApiId=api_id)["items"]}

    code, message = _error(
        lambda: _import_with_backoff(
            lambda: apigw.import_documentation_parts(
                restApiId=api_id, mode="bogus-mode", body=_doc_body("rejected-import")
            )
        )
    )
    assert code == "ValidationException", f"expected ValidationException for an invalid mode, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'bogus-mode' at 'mode' failed to satisfy constraint: "
        "Member must satisfy enum value set: [overwrite, merge]"
    ), f"unexpected rejection message {message!r}"

    after_ids = {p["id"] for p in apigw.get_documentation_parts(restApiId=api_id)["items"]}
    assert after_ids == before_ids, (
        f"a rejected import must create nothing: before={before_ids!r} after={after_ids!r}"
    )

    # Positive control: a valid mode value, otherwise identical, commits the part.
    allowed = _import_with_backoff(
        lambda: apigw.import_documentation_parts(
            restApiId=api_id, mode="merge", body=_doc_body("accepted-import")
        )
    )
    assert len(allowed["ids"]) == 1, f"expected the valid-mode import to commit 1 part, got {allowed!r}"
    committed_id = allowed["ids"][0]

    final_ids = {p["id"] for p in apigw.get_documentation_parts(restApiId=api_id)["items"]}
    assert final_ids == before_ids | {committed_id}, (
        f"expected only the valid-mode import's part to be added, got {final_ids!r} "
        f"(before={before_ids!r}, committed={committed_id!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
