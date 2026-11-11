"""list-approval-rule-templates-invalid-max-results-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-approval-rule-templates-invalid-max-results-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApprovalRuleTemplates called with maxResults=0 (the parameter must be a
    non-zero, non-negative integer) raises InvalidMaxResultsException; a valid
    maxResults value succeeds."""
    cc = ctx.client("codecommit")

    code, message = _error(lambda: cc.list_approval_rule_templates(maxResults=0))
    assert code == "InvalidMaxResultsException", f"unexpected code: {code}"
    assert message == "A valid limit is between 1 and 1000", message

    code2, message2 = _error(lambda: cc.list_approval_rule_templates(maxResults=-1))
    assert code2 == "InvalidMaxResultsException", f"unexpected code: {code2}"
    assert message2 == "A valid limit is between 1 and 1000", message2

    # positive control: a valid maxResults succeeds
    resp = cc.list_approval_rule_templates(maxResults=10)
    assert "approvalRuleTemplateNames" in resp, f"missing approvalRuleTemplateNames: {resp!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
