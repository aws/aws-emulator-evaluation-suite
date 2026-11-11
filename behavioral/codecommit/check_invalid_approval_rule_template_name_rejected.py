"""invalid-approval-rule-template-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invalid-approval-rule-template-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApprovalRuleTemplate with a name of unaccepted characters raises
    InvalidApprovalRuleTemplateNameException, distinct from ApprovalRuleTemplateDoesNotExistException
    for a well-formed absent name."""
    cc = ctx.client("codecommit")
    template_name = ctx.unique_name("sim2real-cc-template-")
    content = (
        '{"Version": "2018-11-08", "Statements": '
        '[{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}]}'
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=content,
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(
        approvalRuleTemplateName=template_name,
    ))

    # positive control: the real, well-formed name resolves fine
    got = cc.get_approval_rule_template(
        approvalRuleTemplateName=template_name,
    )["approvalRuleTemplate"]
    assert got["approvalRuleTemplateName"] == template_name, (
        f"expected {template_name!r}, got {got['approvalRuleTemplateName']!r}"
    )

    # malformed name (contains characters the service does not accept in a name)
    malformed_name = "sim2real invalid/name!"
    code, message = _error(lambda: cc.get_approval_rule_template(
        approvalRuleTemplateName=malformed_name,
    ))
    assert code == "InvalidApprovalRuleTemplateNameException", f"unexpected code: {code}"
    assert message == (
        "The name of the approval rule template is not valid. Template names are case "
        "sensitive and can be any valid combination of letters, numbers, periods, "
        "underscores, and dashes between 1 and 100 characters in length. For more "
        "information, see the Limits topic in the AWS CodeCommit User Guide."
    ), message

    # a well-formed but nonexistent name gets the DoesNotExist class instead
    wellformed_absent_name = ctx.unique_name("sim2real-cc-template-absent-")
    code2, message2 = _error(lambda: cc.get_approval_rule_template(
        approvalRuleTemplateName=wellformed_absent_name,
    ))
    assert code2 == "ApprovalRuleTemplateDoesNotExistException", f"unexpected code: {code2}"
    assert message2 == (
        "No approval rule template exists in this AWS Region with the following name: "
        f"{wellformed_absent_name}. Make sure that you are signed in to the AWS Region "
        "where you created the rule, and then try again."
    ), message2


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
