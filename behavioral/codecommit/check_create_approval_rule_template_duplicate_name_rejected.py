"""create-approval-rule-template-duplicate-name-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-approval-rule-template-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second approval rule template with a used name raises
    ApprovalRuleTemplateNameAlreadyExistsException and leaves the original's content, while a
    different name creates."""
    cc = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-artdup-")

    content_v1 = json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [
                {
                    "Type": "Approvers",
                    "NumberOfApprovalsNeeded": 1,
                }
            ],
        }
    )
    created = cc.create_approval_rule_template(
        approvalRuleTemplateName=name, approvalRuleTemplateContent=content_v1
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=name))
    original_sha = created["approvalRuleTemplate"]["ruleContentSha256"]

    content_v2 = json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [
                {
                    "Type": "Approvers",
                    "NumberOfApprovalsNeeded": 2,
                }
            ],
        }
    )
    code, message = _error(
        lambda: cc.create_approval_rule_template(
            approvalRuleTemplateName=name, approvalRuleTemplateContent=content_v2
        )
    )
    assert code == "ApprovalRuleTemplateNameAlreadyExistsException", code
    expected = (
        "The approval rule template cannot be created because a template with that name "
        "already exists in your AWS account."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the original template's content/hash is untouched by the rejected create
    got = cc.get_approval_rule_template(approvalRuleTemplateName=name)
    assert got["approvalRuleTemplate"]["ruleContentSha256"] == original_sha

    # positive control: a template with a different name is created successfully
    other_name = ctx.unique_name("sim2real-behav-artdup2-")
    cc.create_approval_rule_template(
        approvalRuleTemplateName=other_name, approvalRuleTemplateContent=content_v2
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=other_name))

    # terminal read is independent of the mutating create, at the destination
    other = cc.get_approval_rule_template(approvalRuleTemplateName=other_name)["approvalRuleTemplate"]
    assert other["approvalRuleTemplateName"] == other_name, other


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
