"""get-findings-report-status-no-report-returns-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-findings-report-status-no-report-returns-not-found"
GROUP = "error-semantics"
SERVICES = ["inspector2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFindingsReportStatus with no reportId and no report ever created fails with ResourceNotFoundException."""
    inspector2 = ctx.client("inspector2")

    code, msg = _error_code(lambda: inspector2.get_findings_report_status())
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert msg == "No report was found for this account", msg

    # Positive control: a related, always-available read operation still succeeds.
    resp = inspector2.list_usage_totals()
    assert "totals" in resp, f"expected 'totals' in list_usage_totals response, got keys {list(resp)!r}"


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
