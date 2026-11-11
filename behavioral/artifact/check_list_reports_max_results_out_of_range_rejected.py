"""list-reports-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-reports-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListReports rejects maxResults above the documented [1, 300] range with
    ValidationException, while maxResults=300 (the upper boundary) still succeeds
    in the same file."""
    art = ctx.client("artifact")

    # Positive control: the documented upper boundary succeeds.
    ok = art.list_reports(maxResults=300)
    reports = ok["reports"]
    assert isinstance(reports, list), f"expected reports to be a list, got {type(reports)!r}"

    code, message = _error(lambda: art.list_reports(maxResults=301))
    assert code == "ValidationException", f"expected ValidationException for maxResults=301, got {code}"
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 300"
    )
    assert message == expected, f"expected AWS's exact refusal message, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
