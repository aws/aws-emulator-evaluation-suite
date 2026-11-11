"""cancel-zonal-shift-malformed-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-zonal-shift-malformed-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelZonalShift with an id breaking ^[A-Za-z0-9-]+$ fails ValidationException with AWS's pattern
    message, while a well-formed unknown id fails AccessDeniedException with an empty message."""
    arc = ctx.client("arc-zonal-shift")

    code, message = _error_detail(lambda: arc.cancel_zonal_shift(zonalShiftId="bad_id_1"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    expected_message = (
        "1 validation error detected: Value at 'zonalShiftId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [A-Za-z0-9-]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control, same operation: a well-formed but nonexistent id hits a
    # different boundary. Without this, a target that returns ValidationException
    # for every CancelZonalShift call would pass just as well as one that actually
    # enforces the pattern.
    well_formed_missing_id = ctx.unique_name("sim2real-arczs-")
    other_code, other_message = _error_detail(
        lambda: arc.cancel_zonal_shift(zonalShiftId=well_formed_missing_id)
    )
    assert other_code == "AccessDeniedException", (
        f"well-formed but nonexistent id: expected AccessDeniedException, got {other_code!r}"
    )
    # Real AWS sends this AccessDeniedException with an empty message.
    assert other_message == "", f"expected an empty AccessDeniedException message, got {other_message!r}"

    # Positive control: the API itself is healthy for this account/region.
    resp = arc.list_zonal_shifts()
    assert "items" in resp, f"expected 'items' key in ListZonalShifts response, got {resp!r}"


def _error_detail(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
