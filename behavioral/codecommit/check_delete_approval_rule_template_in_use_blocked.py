"""delete-approval-rule-template-in-use-blocked."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-approval-rule-template-in-use-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]

_TEMPLATE_CONTENT = (
    '{"Version": "2018-11-08","Statements": '
    '[{"Type": "Approvers","NumberOfApprovalsNeeded": 1}]}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApprovalRuleTemplate on a template that is still associated with a
    repository must be rejected with ApprovalRuleTemplateInUseException instead of
    silently deleting the template and orphaning the association."""
    cc = ctx.client("codecommit")
    template_name = ctx.unique_name("sim2real-behav-artiu-")
    repo_name = ctx.unique_name("sim2real-behav-artiu-repo-")

    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=_TEMPLATE_CONTENT
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: cc.delete_approval_rule_template(
        approvalRuleTemplateName=template_name
    )))

    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "artiu"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: cc.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )))

    code, message = _error(
        lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)
    )
    assert code == "ApprovalRuleTemplateInUseException", (
        f"expected ApprovalRuleTemplateInUseException, got {code!r}"
    )
    expected = (
        "The approval rule template cannot be deleted because it is associated with one or more "
        "repositories. You cannot delete a template if it is associated with a repository. "
        "Disassociate the template from all repositories in your AWS account, and then try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the template must still exist, fully intact, and the
    # association that blocked the delete must still hold.
    still_there = cc.get_approval_rule_template(approvalRuleTemplateName=template_name)
    assert still_there["approvalRuleTemplate"]["approvalRuleTemplateName"] == template_name, (
        f"template {template_name!r} vanished despite the rejected delete"
    )
    still_associated = cc.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name in still_associated, (
        f"expected {repo_name!r} still associated with {template_name!r}, got {still_associated!r}"
    )

    # Positive control: once the association is removed, deletion succeeds.
    cc.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)

    code2, message2 = _error(
        lambda: cc.get_approval_rule_template(approvalRuleTemplateName=template_name)
    )
    assert code2 == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected ApprovalRuleTemplateDoesNotExistException after delete, got {code2!r}"
    )
    expected2 = (
        "No approval rule template exists in this AWS Region with the following name: "
        f"{template_name}. Make sure that you are signed in to the AWS Region where you created "
        "the rule, and then try again."
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
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
