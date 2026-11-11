"""get-documentation-part-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-documentation-part-not-found"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDocumentationPart returns a real part (positive control) and fails with
    NotFoundException and its exact message for an unknown part id."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-bhv-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    part_id = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties='{"description": "sim2real doc part"}',
    )["id"]

    # Positive control: the real part is readable through the same operation.
    control = apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    assert control["id"] == part_id, (
        f"positive control: expected GetDocumentationPart to return id {part_id!r}, got {control!r}"
    )

    # A syntactically plausible but never-issued documentation part id.
    bogus_id = "zzzzzz"
    code, message = _error(lambda: apigw.get_documentation_part(restApiId=api_id, documentationPartId=bogus_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Invalid Documentation part identifier specified", (
        f"unexpected NotFoundException message {message!r}"
    )


def _error(fn: Any) -> tuple[str | None, str | None]:
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An unexpected SUCCESS
    raises, because an emulator accepting a bogus id real AWS refuses is the strongest signal
    available and must not be reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
