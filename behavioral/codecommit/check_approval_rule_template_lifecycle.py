"""approval-rule-template-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "approval-rule-template-lifecycle"
GROUP = "state-machine"
SERVICES = ["codecommit"]


def _content(num_approvals: int) -> str:
    return json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [
                {"Type": "Approvers", "NumberOfApprovalsNeeded": num_approvals}
            ],
        }
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApprovalRuleTemplate -> Get returns it -> UpdateContent changes it -> Delete removes it."""
    cc = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-art-")
    initial_content = _content(1)

    created = cc.create_approval_rule_template(
        approvalRuleTemplateName=name,
        approvalRuleTemplateContent=initial_content,
        approvalRuleTemplateDescription="initial description",
    )["approvalRuleTemplate"]

    def _cleanup():
        try:
            cc.delete_approval_rule_template(approvalRuleTemplateName=name)
        except cc.exceptions.ApprovalRuleTemplateDoesNotExistException:
            pass

    ctx.on_cleanup(_cleanup)

    template_id = created["approvalRuleTemplateId"]
    sha_before = created["ruleContentSha256"]

    got = cc.get_approval_rule_template(approvalRuleTemplateName=name)["approvalRuleTemplate"]
    assert got["approvalRuleTemplateId"] == template_id, (
        f"GetApprovalRuleTemplate returned a different id: expected={template_id!r} actual={got['approvalRuleTemplateId']!r}"
    )
    assert got["approvalRuleTemplateName"] == name, (
        f"GetApprovalRuleTemplate returned a different name: expected={name!r} actual={got['approvalRuleTemplateName']!r}"
    )
    assert json.loads(got["approvalRuleTemplateContent"]) == json.loads(initial_content), (
        f"GetApprovalRuleTemplate content mismatch: expected={initial_content!r} actual={got['approvalRuleTemplateContent']!r}"
    )
    assert got["ruleContentSha256"] == sha_before, (
        f"ruleContentSha256 drifted between Create and Get with no update in between: "
        f"expected={sha_before!r} actual={got['ruleContentSha256']!r}"
    )

    updated_content = _content(2)
    updated = cc.update_approval_rule_template_content(
        approvalRuleTemplateName=name,
        newRuleContent=updated_content,
    )["approvalRuleTemplate"]
    assert json.loads(updated["approvalRuleTemplateContent"]) == json.loads(updated_content), (
        f"UpdateApprovalRuleTemplateContent did not return the new content: "
        f"expected={updated_content!r} actual={updated['approvalRuleTemplateContent']!r}"
    )
    assert updated["ruleContentSha256"] != sha_before, (
        f"ruleContentSha256 unchanged after content update: still {sha_before!r}"
    )

    got_after_update = cc.get_approval_rule_template(approvalRuleTemplateName=name)["approvalRuleTemplate"]
    assert json.loads(got_after_update["approvalRuleTemplateContent"]) == json.loads(updated_content), (
        f"GetApprovalRuleTemplate returned stale content after the update: "
        f"expected={updated_content!r} actual={got_after_update['approvalRuleTemplateContent']!r}"
    )

    cc.delete_approval_rule_template(approvalRuleTemplateName=name)

    code, message = _error(lambda: cc.get_approval_rule_template(approvalRuleTemplateName=name))
    assert code == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected ApprovalRuleTemplateDoesNotExistException after delete, got {code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {name}. Make sure that you are signed in to the AWS Region where "
        "you created the rule, and then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
