"""approval-rule-template-content-update-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "approval-rule-template-content-update-preserved"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApprovalRuleTemplateContent replaces the template's content
    exactly as supplied (not a merge of old and new), and GetApprovalRuleTemplate
    reflects the new content verbatim."""
    cc = ctx.client("codecommit")

    template_name = ctx.unique_name("sim2real-cc-art-")

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    content_v1 = json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [
                {
                    "Type": "Approvers",
                    "NumberOfApprovalsNeeded": 1,
                    "ApprovalPoolMembers": [
                        f"arn:aws:sts::{account_id}:assumed-role/CodeCommitReview/*"
                    ],
                }
            ],
        }
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=content_v1,
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    # Deliberately different JSON whitespace/formatting and a different, larger
    # structure than content_v1.
    content_v2 = json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [
                {
                    "Type": "Approvers",
                    "NumberOfApprovalsNeeded": 2,
                    "ApprovalPoolMembers": [
                        f"arn:aws:sts::{account_id}:assumed-role/AnotherReviewRole/*"
                    ],
                }
            ],
        },
        indent=4,
        sort_keys=True,
    )

    cc.update_approval_rule_template_content(
        approvalRuleTemplateName=template_name,
        newRuleContent=content_v2,
    )

    fetched = cc.get_approval_rule_template(approvalRuleTemplateName=template_name)
    fetched_content = fetched["approvalRuleTemplate"]["approvalRuleTemplateContent"]

    assert json.loads(fetched_content) == json.loads(content_v2), fetched_content
    assert "AnotherReviewRole" in fetched_content, (
        f"expected updated pool member 'AnotherReviewRole' in stored content, "
        f"actual={fetched_content!r}"
    )
    assert "CodeCommitReview" not in fetched_content, (
        "old content leaked into the updated template -- update must replace, not merge"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
