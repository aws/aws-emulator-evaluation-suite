"""get-listing-malformed-id-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-listing-malformed-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetListing rejects a listingId that violates the ^[\\w\\-]+$ pattern constraint with
    ValidationException, distinct from a well-formed-but-missing id which is a ResourceNotFound."""
    md = ctx.client("marketplace-discovery")

    error = _error(lambda: md.get_listing(listingId="not a valid id!"))
    assert error.get("Code") == "ValidationException", error
    expected_message = (
        "1 validation error detected: Value 'not a valid id!' at 'listingId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w\\-]+"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # positive control, same file: a well-formed (merely nonexistent) id passes pattern
    # validation and fails only at the not-found stage -- proving the rejection above is
    # specifically about the malformed pattern, not a blanket failure.
    control_id = ctx.unique_name("sim2real-well-formed-control-")
    control_error = _error(lambda: md.get_listing(listingId=control_id))
    assert control_error.get("Code") == "ResourceNotFoundException", control_error
    assert control_error.get("Message") == "Listing not found", control_error


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
