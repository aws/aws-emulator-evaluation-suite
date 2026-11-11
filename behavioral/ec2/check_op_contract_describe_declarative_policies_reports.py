"""op-contract-describe-declarative-policies-reports."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-declarative-policies-reports"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDeclarativePoliciesReports: list-shape success (no report generation
    required to call it), the DryRun permission-check contract, and the nonexistent
    ReportIds contract (filtered by an id that cannot exist)."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_declarative_policies_reports()
    assert "Reports" in resp, f"expected a 'Reports' key, got keys={sorted(resp.keys())}"
    assert isinstance(resp["Reports"], list), f"expected Reports to be a list, got {type(resp['Reports'])!r}"

    dry_code, dry_code_msg = _error(lambda: ec2.describe_declarative_policies_reports(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
    )

    # Pagination round-trip contract: MaxResults is honored and the response shape is
    # stable even when there is nothing to page through.
    resp2 = ec2.describe_declarative_policies_reports(MaxResults=5)
    assert "Reports" in resp2, f"expected a 'Reports' key with MaxResults set, got keys={sorted(resp2.keys())}"
    assert isinstance(resp2["Reports"], list), (
        f"expected Reports to be a list with MaxResults set, got {type(resp2['Reports'])!r}"
    )

    # Filtering by a well-formed but nonexistent ReportId is rejected outright, not
    # answered with an empty list.
    bogus_id = "dpr-00000000000000000"
    bogus_code, bogus_code_msg = _error(lambda: ec2.describe_declarative_policies_reports(ReportIds=[bogus_id]))
    assert bogus_code == "InvalidDeclarativePoliciesReportId.NotFound", (
        f"expected InvalidDeclarativePoliciesReportId.NotFound for nonexistent ReportId "
        f"{bogus_id!r}, got {bogus_code}"
    )
    assert bogus_code_msg == f"The report ID '{bogus_id}' does not exist.", (
        f"expected the exact InvalidDeclarativePoliciesReportId.NotFound message, got {bogus_code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
