"""op-contract-get-declarative-policies-report-summary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-declarative-policies-report-summary"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeclarativePoliciesReportSummary's DryRun permission check succeeds
    independently of report existence, while a real call against a nonexistent
    report id is rejected distinctly."""
    ec2 = ctx.client("ec2")

    bogus_report_id = "dpr-00000000000000000"

    # Success-path contract proxy: DryRun proves the request is well-formed and
    # authorized, independent of whether the report actually exists.
    dry_run_code, dry_run_message = _error(
        lambda: ec2.get_declarative_policies_report_summary(
            ReportId=bogus_report_id, DryRun=True
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == _DRY_RUN_MESSAGE, (
        f"expected DryRun message {_DRY_RUN_MESSAGE!r}, got {dry_run_message!r}"
    )

    # Error boundary: without DryRun, a nonexistent report id must be rejected distinctly.
    code, message = _error(
        lambda: ec2.get_declarative_policies_report_summary(ReportId=bogus_report_id)
    )
    assert code == "InvalidDeclarativePoliciesReportId.NotFound", (
        "expected InvalidDeclarativePoliciesReportId.NotFound for a nonexistent "
        f"declarative policies report id, got {code!r}"
    )
    expected = f"The declarative-policies-report ID '{bogus_report_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
