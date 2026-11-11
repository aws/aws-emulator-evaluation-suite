"""approval-rule-template-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "approval-rule-template-name-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]

_CONTENT_A = (
    '{"Version": "2018-11-08","Statements": '
    '[{"Type": "Approvers","NumberOfApprovalsNeeded": 1}]}'
)
_CONTENT_B = (
    '{"Version": "2018-11-08","Statements": '
    '[{"Type": "Approvers","NumberOfApprovalsNeeded": 2}]}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a template under a taken name, or renaming one onto it, fails with
    ApprovalRuleTemplateNameAlreadyExistsException and leaves the existing template untouched;
    once the name is freed the identical rename succeeds, so the occupied name was the cause."""
    cc = ctx.client("codecommit")
    name_a = ctx.unique_name("sim2real-behav-artnc-a-")
    name_b = ctx.unique_name("sim2real-behav-artnc-b-")

    original_a = cc.create_approval_rule_template(
        approvalRuleTemplateName=name_a, approvalRuleTemplateContent=_CONTENT_A
    )["approvalRuleTemplate"]
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=name_a))
    )

    # 1) CreateApprovalRuleTemplate with a name that already exists is rejected.
    create_code, create_message = _error(
        lambda: cc.create_approval_rule_template(
            approvalRuleTemplateName=name_a, approvalRuleTemplateContent=_CONTENT_B
        )
    )
    assert create_code == "ApprovalRuleTemplateNameAlreadyExistsException", (
        f"create with an occupied name must be refused with "
        f"ApprovalRuleTemplateNameAlreadyExistsException; got {create_code!r}"
    )
    expected_message = (
        "The approval rule template cannot be created because a template with "
        "that name already exists in your AWS account."
    )
    assert create_message == expected_message, (
        f"expected message {expected_message!r}, got {create_message!r}"
    )

    unchanged_a = cc.get_approval_rule_template(approvalRuleTemplateName=name_a)[
        "approvalRuleTemplate"
    ]
    assert unchanged_a["ruleContentSha256"] == original_a["ruleContentSha256"], (
        f"the rejected create must not overwrite the pre-existing template's content: "
        f"expected sha {original_a['ruleContentSha256']!r}, got "
        f"{unchanged_a['ruleContentSha256']!r}"
    )

    # 2) UpdateApprovalRuleTemplateName renaming a second template to name_a is rejected.
    created_b = cc.create_approval_rule_template(
        approvalRuleTemplateName=name_b, approvalRuleTemplateContent=_CONTENT_B
    )["approvalRuleTemplate"]
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=name_b))
    )

    def _rename_b_to_a():
        return cc.update_approval_rule_template_name(
            oldApprovalRuleTemplateName=name_b, newApprovalRuleTemplateName=name_a
        )

    rename_code, rename_message = _error(_rename_b_to_a)
    assert rename_code == "ApprovalRuleTemplateNameAlreadyExistsException", (
        f"renaming onto an occupied name must be refused with "
        f"ApprovalRuleTemplateNameAlreadyExistsException; got {rename_code!r}"
    )
    expected_message = (
        "The approval rule template cannot be created because a template with "
        "that name already exists in your AWS account."
    )
    assert rename_message == expected_message, (
        f"expected message {expected_message!r}, got {rename_message!r}"
    )

    # Effect absent: name_b still exists under its own name, name_a is still content_a.
    still_b = cc.get_approval_rule_template(approvalRuleTemplateName=name_b)["approvalRuleTemplate"]
    assert still_b["approvalRuleTemplateName"] == name_b, (
        f"the rejected rename must leave the source template under its own name: "
        f"expected {name_b!r}, got {still_b['approvalRuleTemplateName']!r}"
    )
    still_a = cc.get_approval_rule_template(approvalRuleTemplateName=name_a)["approvalRuleTemplate"]
    assert still_a["ruleContentSha256"] == original_a["ruleContentSha256"], (
        f"the rejected rename must not touch the template already at the target name: "
        f"expected sha {original_a['ruleContentSha256']!r}, got "
        f"{still_a['ruleContentSha256']!r}"
    )

    # Restore: free the occupied name by deleting the template that was blocking it.
    cc.delete_approval_rule_template(approvalRuleTemplateName=name_a)

    # Retry the IDENTICAL rename that was just refused: it must now succeed, which is
    # what proves the earlier refusal was caused by the name being taken and nothing
    # else -- and doubles as the positive control that the rename operation itself works.
    renamed = _rename_b_to_a()["approvalRuleTemplate"]
    assert renamed["approvalRuleTemplateName"] == name_a, (
        f"once the name is freed, the identical rename must succeed: expected "
        f"{name_a!r}, got {renamed['approvalRuleTemplateName']!r}"
    )
    assert renamed["ruleContentSha256"] == created_b["ruleContentSha256"], (
        f"the renamed template must still carry the content it had as name_b, "
        f"not the deleted original's: expected sha {created_b['ruleContentSha256']!r}, "
        f"got {renamed['ruleContentSha256']!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error as (code, message). A success raises, so a target
    accepting a call AWS refuses fails as itself rather than as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


_GONE_CODES = ("ApprovalRuleTemplateDoesNotExistException", "RepositoryDoesNotExistException")


def _unless_gone(fn):
    """Run teardown step fn(); only a not-found error (already gone) is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in _GONE_CODES:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
