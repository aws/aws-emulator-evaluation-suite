"""approval-rule-template-name-already-exists-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "approval-rule-template-name-already-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating a second approval rule template with a name already in use raises
    ApprovalRuleTemplateNameAlreadyExistsException and leaves the original
    template's content untouched."""
    cc = ctx.client("codecommit")
    template_name = ctx.unique_name("sim2real-cc-template-")
    original_content = (
        '{"Version": "2018-11-08", "Statements": '
        '[{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}]}'
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=original_content,
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(
        approvalRuleTemplateName=template_name,
    ))

    conflicting_content = (
        '{"Version": "2018-11-08", "Statements": '
        '[{"Type": "Approvers", "NumberOfApprovalsNeeded": 2}]}'
    )
    code, message = _error(lambda: cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=conflicting_content,
    ))
    assert code == "ApprovalRuleTemplateNameAlreadyExistsException", (
        f"expected ApprovalRuleTemplateNameAlreadyExistsException, got: {code}"
    )
    expected_message = (
        "The approval rule template cannot be created because a template with "
        "that name already exists in your AWS account."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # The service may reformat the stored JSON (whitespace/ordering), so compare
    # semantically rather than byte-for-byte: the original's "NumberOfApprovalsNeeded"
    # of 1 must still be in effect, not the rejected create's value of 2.
    import json
    current = cc.get_approval_rule_template(
        approvalRuleTemplateName=template_name,
    )["approvalRuleTemplate"]
    current_needed = json.loads(current["approvalRuleTemplateContent"])["Statements"][0][
        "NumberOfApprovalsNeeded"
    ]
    assert current_needed == 1, f"template content was overwritten: expected 1, got {current_needed}"

    # restore: the name conflict is what blocked the create above, not something
    # incidental. Remove the original template that was holding the name, then
    # replay the identical call that was just rejected and demand it now succeeds.
    cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)
    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=conflicting_content,
    )
    restored = cc.get_approval_rule_template(
        approvalRuleTemplateName=template_name,
    )["approvalRuleTemplate"]
    restored_needed = json.loads(restored["approvalRuleTemplateContent"])["Statements"][0][
        "NumberOfApprovalsNeeded"
    ]
    assert restored_needed == 2, (
        f"identical create did not succeed once the name was freed: expected 2, got {restored_needed}"
    )

    # positive control: a distinct name succeeds and keeps its own content
    other_name = ctx.unique_name("sim2real-cc-template-other-")
    cc.create_approval_rule_template(
        approvalRuleTemplateName=other_name, approvalRuleTemplateContent=conflicting_content,
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=other_name))
    other = cc.get_approval_rule_template(approvalRuleTemplateName=other_name)["approvalRuleTemplate"]
    other_needed = json.loads(other["approvalRuleTemplateContent"])["Statements"][0][
        "NumberOfApprovalsNeeded"
    ]
    assert other_needed == 2, f"distinct-name create lost its own content: expected 2, got {other_needed}"


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
