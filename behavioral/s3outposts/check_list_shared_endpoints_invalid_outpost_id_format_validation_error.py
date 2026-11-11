"""list-shared-endpoints-invalid-outpost-id-format-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-shared-endpoints-invalid-outpost-id-format-validation-error"
GROUP = "validation"
SERVICES = ["s3outposts"]

VALIDATION_PREFIX = "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: "
OUTPOST_ID_PATTERN = r"^(op-[a-f0-9]{17}|\d{12}|ec2)$"
ACCESS_DENIED = "Access Denied"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSharedEndpoints rejects a malformed OutpostId with ValidationException -- distinct
    from the ResourceNotFoundException a well-formed but unknown OutpostId gets."""
    s3o = ctx.client("s3outposts")

    bad_code, bad_message = _error(
        lambda: s3o.list_shared_endpoints(OutpostId="invalid-format-id")
    )
    assert bad_code == "ValidationException", (
        f"expected ValidationException for a malformed OutpostId, got {bad_code!r}"
    )
    expected = VALIDATION_PREFIX.format("invalid-format-id", "outpostId") + (
        "Member must satisfy regular expression pattern: " + OUTPOST_ID_PATTERN
    )
    assert bad_message == expected, f"message={bad_message!r}"

    # Positive control: a well-formed but unknown OutpostId must fail differently, isolating
    # the pattern mismatch as the cause of the ValidationException above.
    control_code, control_message = _error(
        lambda: s3o.list_shared_endpoints(OutpostId="op-" + "0" * 17)
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but unknown OutpostId, "
        f"got {control_code!r}"
    )
    assert control_message == ACCESS_DENIED, f"message={control_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
