"""list-zonal-shifts-invalid-status-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-zonal-shifts-invalid-status-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListZonalShifts rejects a status filter value outside the ACTIVE|EXPIRED|CANCELED enum
    boundary, while the same call with a valid enum value still succeeds (positive control)."""
    arc = ctx.client("arc-zonal-shift")

    code, message = _error_detail(lambda: arc.list_zonal_shifts(status="PENDING"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    expected_message = (
        "1 validation error detected: Value at 'status' failed to satisfy constraint: "
        "Member must satisfy enum value set: [EXPIRED, ACTIVE, CANCELED]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a syntactically valid status value is accepted.
    resp = arc.list_zonal_shifts(status="ACTIVE")
    assert "items" in resp, f"expected 'items' key in ListZonalShifts(status=ACTIVE) response, got keys={sorted(resp.keys())}"


def _error_detail(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
