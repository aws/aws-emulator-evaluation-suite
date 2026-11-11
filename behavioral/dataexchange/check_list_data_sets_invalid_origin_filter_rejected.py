"""list-data-sets-invalid-origin-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-data-sets-invalid-origin-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDataSets rejects an Origin filter value outside the OWNED/ENTITLED enum with
    ValidationException, while the same call with a valid Origin filter succeeds."""
    dx = ctx.client("dataexchange")

    # Positive control: a valid Origin filter succeeds and returns a DataSets list.
    baseline = dx.list_data_sets(Origin="OWNED", MaxResults=10)
    assert "DataSets" in baseline, f"expected a DataSets list, got {baseline!r}"

    code, message = _error(lambda: dx.list_data_sets(Origin="NOT_A_REAL_ORIGIN"))
    assert code == "ValidationException", (
        f"expected ValidationException for an Origin outside OWNED/ENTITLED, got {code!r}"
    )
    assert message == 'The following parameter(s) are not valid: "origin" must be one of [OWNED, ENTITLED].', f"expected the exact refusal message, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
