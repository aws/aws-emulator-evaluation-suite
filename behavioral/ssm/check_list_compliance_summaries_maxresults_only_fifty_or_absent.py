"""list-compliance-summaries-maxresults-only-fifty-or-absent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-compliance-summaries-maxresults-only-fifty-or-absent"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_NOT_FIFTY = (
    "ValidationException",
    "ListComplianceSummaries only support MaxResults as null or 50",
)
_OVER_RANGE = (
    "ValidationException",
    "1 validation error detected: Value '51' at 'maxResults' failed to satisfy constraint: "
    "Member must have value less than or equal to 50",
)


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) raised by ``fn``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListComplianceSummaries rejects any MaxResults other than exactly 50, though the model's
    range is documented as 1-50, and accepts 50 or an absent MaxResults."""
    ssm = ctx.client("ssm")
    # A ComplianceType no PutComplianceItems call ever used, so a filtered read is empty
    # regardless of compliance data another check in this run may have written.
    never_used_type = [{"Key": "ComplianceType", "Values": [ctx.unique_name("sim2real-compliance-type-")]}]

    for bad in (1, 2, 49):
        got = _error(
            lambda bad=bad: ssm.list_compliance_summaries(Filters=never_used_type, MaxResults=bad)
        )
        assert got == _NOT_FIFTY, f"MaxResults={bad}: expected {_NOT_FIFTY!r}, got {got!r}"

    got = _error(lambda: ssm.list_compliance_summaries(Filters=never_used_type, MaxResults=51))
    assert got == _OVER_RANGE, f"MaxResults=51: expected {_OVER_RANGE!r}, got {got!r}"

    fifty = ssm.list_compliance_summaries(Filters=never_used_type, MaxResults=50)
    assert fifty["ComplianceSummaryItems"] == [], (
        f"a filter on a ComplianceType no item carries returned {fifty['ComplianceSummaryItems']!r}"
    )

    absent = ssm.list_compliance_summaries(Filters=never_used_type)
    assert absent["ComplianceSummaryItems"] == [], (
        f"a filter on a ComplianceType no item carries returned {absent['ComplianceSummaryItems']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
