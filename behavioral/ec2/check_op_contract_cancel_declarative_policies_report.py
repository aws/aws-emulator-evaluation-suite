"""op-contract-cancel-declarative-policies-report."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-cancel-declarative-policies-report"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelDeclarativePoliciesReport fails InvalidDeclarativePoliciesReportId.Malformed for a
    malformed ReportId, while a well-formed nonexistent 'dpr-' id with DryRun fails DryRunOperation,
    each with its exact message.
    """
    ec2 = ctx.client("ec2")

    malformed_code, malformed_code_message = _error_code(
        lambda: ec2.cancel_declarative_policies_report(ReportId="not-a-valid-report-id")
    )
    assert malformed_code == "InvalidDeclarativePoliciesReportId.Malformed", (
        f"expected InvalidDeclarativePoliciesReportId.Malformed, got {malformed_code}"
    )
    expected_malformed_code_message = "The declarative-policies-report ID 'not-a-valid-report-id' is malformed"
    assert malformed_code_message == expected_malformed_code_message, f"expected message {expected_malformed_code_message!r}, got {malformed_code_message!r}"

    dry_run_code, dry_run_code_message = _error_code(
        lambda: ec2.cancel_declarative_policies_report(
            ReportId="dpr-00000000000000000", DryRun=True
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code}"
    expected_dry_run_code_message = "Request would have succeeded, but DryRun flag is set."
    assert dry_run_code_message == expected_dry_run_code_message, f"expected message {expected_dry_run_code_message!r}, got {dry_run_code_message!r}"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
