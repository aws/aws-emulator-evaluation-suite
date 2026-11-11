"""approval-rule-template-content-preserved-verbatim."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

CHECK = "approval-rule-template-content-preserved-verbatim"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CodeCommit stores approval-rule-template JSON minified (no insignificant whitespace),
    preserving key order and every value verbatim, on both create and update."""
    cc = ctx.client("codecommit")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    template_name = ctx.unique_name("sim2real-behav-cc-art-")

    original_obj = {
        "Version": "2018-11-08",
        "DestinationReferences": ["refs/heads/main", "refs/heads/release/*"],
        "Statements": [
            {
                "Type": "Approvers",
                "NumberOfApprovalsNeeded": 2,
                "ApprovalPoolMembers": [
                    f"arn:aws:sts::{account_id}:assumed-role/CodeCommitReview/*",
                    f"arn:aws:iam::{account_id}:user/Mary_Major",
                ],
            }
        ],
    }
    # Submitted pretty-printed to observe whether the service canonicalizes whitespace.
    submitted_content = json.dumps(original_obj, indent=2)
    # The canonical form CodeCommit is expected to store/return: same key order, same
    # values, but minified (no spaces after ':' or ',').
    canonical_content = json.dumps(original_obj, separators=(",", ":"))

    created = cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=submitted_content,
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    actual_created = created["approvalRuleTemplate"]["approvalRuleTemplateContent"]
    assert actual_created == canonical_content, (
        f"expected canonicalized (minified) content, expected={canonical_content!r} "
        f"actual={actual_created!r}"
    )
    assert json.loads(actual_created) == original_obj, (
        f"parsed created content diverged from what was submitted: "
        f"expected={original_obj!r} actual={json.loads(actual_created)!r}"
    )

    expected_sha_1 = hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()
    assert created["approvalRuleTemplate"]["ruleContentSha256"] == expected_sha_1, (
        "ruleContentSha256 does not match sha256 of the canonicalized content actually stored"
    )

    fetched = cc.get_approval_rule_template(approvalRuleTemplateName=template_name)
    actual1 = fetched["approvalRuleTemplate"]["approvalRuleTemplateContent"]
    assert actual1 == canonical_content, f"expected={canonical_content!r} actual={actual1!r}"

    # A third key order (neither alphabetical nor the create leg's), so this leg pins that the
    # update preserves the order THIS call submitted.
    updated_obj = {
        "Statements": [
            {
                "Type": "Approvers",
                "NumberOfApprovalsNeeded": 1,
                "ApprovalPoolMembers": [
                    f"arn:aws:iam::{account_id}:user/Nikhil_Jayashankar",
                ],
            }
        ],
        "Version": "2018-11-08",
        "DestinationReferences": ["refs/heads/main"],
    }
    submitted_update = json.dumps(updated_obj, indent=4)
    canonical_update = json.dumps(updated_obj, separators=(",", ":"))

    updated = cc.update_approval_rule_template_content(
        approvalRuleTemplateName=template_name,
        newRuleContent=submitted_update,
        existingRuleContentSha256=expected_sha_1,
    )
    actual_updated = updated["approvalRuleTemplate"]["approvalRuleTemplateContent"]
    assert actual_updated == canonical_update, (
        f"expected={canonical_update!r} actual={actual_updated!r}"
    )
    expected_sha_2 = hashlib.sha256(canonical_update.encode("utf-8")).hexdigest()
    assert updated["approvalRuleTemplate"]["ruleContentSha256"] == expected_sha_2, (
        f"expected ruleContentSha256={expected_sha_2!r} "
        f"actual={updated['approvalRuleTemplate']['ruleContentSha256']!r}"
    )
    assert expected_sha_2 != expected_sha_1, (
        f"content hash did not change across the update: both are {expected_sha_1!r}"
    )

    fetched_after_update = cc.get_approval_rule_template(approvalRuleTemplateName=template_name)
    actual_after_update = fetched_after_update["approvalRuleTemplate"]["approvalRuleTemplateContent"]
    assert actual_after_update == canonical_update, (
        "GetApprovalRuleTemplate returned stale content after UpdateApprovalRuleTemplateContent: "
        f"expected={canonical_update!r} actual={actual_after_update!r}"
    )
    assert actual_after_update != canonical_content, (
        f"content after update still matches the pre-update canonical form {canonical_content!r} "
        "-- update had no effect"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

