"""approval-rule-template-repository-association-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "approval-rule-template-repository-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["codecommit"]

_TEMPLATE_CONTENT = (
    '{"Version":"2018-11-08","Statements":'
    '[{"Type":"Approvers","NumberOfApprovalsNeeded":1}]}'
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An approval rule template transitions through create -> associate ->
    listed-as-associated -> disassociate -> delete, with each state change visible
    via list/get calls."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-art-repo-")
    template_name = ctx.unique_name("sim2real-art-tmpl-")

    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=_TEMPLATE_CONTENT,
        approvalRuleTemplateDescription="sim2real lifecycle check",
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    # Not associated yet.
    repos_before = cc.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name not in repos_before, (
        f"expected {repo_name!r} absent from repos-for-template before association, "
        f"got {repos_before!r}"
    )

    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )

    repos_after_assoc = cc.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name in repos_after_assoc, (
        f"expected {repo_name!r} in repos-for-template after association, got {repos_after_assoc!r}"
    )

    templates_on_repo = cc.list_associated_approval_rule_templates_for_repository(
        repositoryName=repo_name
    )["approvalRuleTemplateNames"]
    assert template_name in templates_on_repo, (
        f"expected {template_name!r} in templates-for-repo after association, got {templates_on_repo!r}"
    )

    # A template still associated with a repository cannot be deleted.
    code, message = _error(
        lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)
    )
    assert code == "ApprovalRuleTemplateInUseException", (
        f"expected ApprovalRuleTemplateInUseException deleting an in-use template, got {code!r}"
    )
    expected_message = (
        "The approval rule template cannot be deleted because it is associated "
        "with one or more repositories. You cannot delete a template if it is "
        "associated with a repository. Disassociate the template from all "
        "repositories in your AWS account, and then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rejected delete must not have touched the template or the association.
    still_exists = cc.get_approval_rule_template(approvalRuleTemplateName=template_name)[
        "approvalRuleTemplate"
    ]
    assert still_exists["approvalRuleTemplateName"] == template_name, (
        f"expected the template to survive the rejected delete, got {still_exists!r}"
    )
    still_associated = cc.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name in still_associated, (
        f"expected {repo_name!r} still associated after the rejected delete, got {still_associated!r}"
    )

    cc.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )

    repos_after_disassoc = cc.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name not in repos_after_disassoc, (
        f"expected {repo_name!r} absent from repos-for-template after disassociation, "
        f"got {repos_after_disassoc!r}"
    )

    templates_after_disassoc = cc.list_associated_approval_rule_templates_for_repository(
        repositoryName=repo_name
    )["approvalRuleTemplateNames"]
    assert template_name not in templates_after_disassoc, (
        f"expected {template_name!r} absent from templates-for-repo after disassociation, "
        f"got {templates_after_disassoc!r}"
    )

    # Now deletable since no longer associated with any repository — the identical call
    # that was just rejected now succeeds.
    cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)

    all_names = cc.list_approval_rule_templates()["approvalRuleTemplateNames"]
    assert template_name not in all_names, (
        f"expected {template_name!r} absent from list-templates after delete, got {all_names!r}"
    )

    gone_code, gone_message = _error(
        lambda: cc.get_approval_rule_template(approvalRuleTemplateName=template_name)
    )
    assert gone_code == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected ApprovalRuleTemplateDoesNotExistException reading the deleted template, "
        f"got {gone_code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {template_name}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
    )
    assert gone_message == expected_message, (
        f"expected message {expected_message!r}, got {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
