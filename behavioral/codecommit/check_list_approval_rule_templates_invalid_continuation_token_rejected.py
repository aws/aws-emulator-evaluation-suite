"""list-approval-rule-templates-invalid-continuation-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-approval-rule-templates-invalid-continuation-token-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApprovalRuleTemplates called with a garbage continuation token raises
    InvalidContinuationTokenException; omitting the token entirely succeeds."""
    cc = ctx.client("codecommit")

    token = "not-a-real-continuation-token"
    code, message = _error(lambda: cc.list_approval_rule_templates(nextToken=token))
    assert code == "InvalidContinuationTokenException", f"unexpected code: {code}"
    assert message == f"Error parsing next token: {token}", message

    # positive control: no token at all succeeds
    resp = cc.list_approval_rule_templates()
    assert "approvalRuleTemplateNames" in resp, f"missing approvalRuleTemplateNames: {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a garbage continuation token real AWS refuses is the strongest signal
    available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
