"""approval-rule-template-delete-in-use-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "approval-rule-template-delete-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a template still associated with a repository is rejected; disassociating first allows it."""
    cc = ctx.client("codecommit")
    template_name = _create_template(ctx)
    repo_name = _create_repo(ctx)

    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )

    code, message = _error(
        lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)
    )
    assert code == "ApprovalRuleTemplateInUseException", (
        f"expected ApprovalRuleTemplateInUseException, got {code!r}"
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

    # effect absent: the template still exists and is still associated with the repository
    still_there = cc.get_approval_rule_template(approvalRuleTemplateName=template_name)[
        "approvalRuleTemplate"
    ]
    assert still_there["approvalRuleTemplateName"] == template_name, (
        f"template {template_name!r} vanished despite the rejected delete"
    )
    still_associated = cc.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name in still_associated, (
        f"expected {repo_name!r} still associated with {template_name!r}, got {still_associated!r}"
    )

    # positive control: once disassociated, delete succeeds
    cc.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)

    code_after, message_after = _error(
        lambda: cc.get_approval_rule_template(approvalRuleTemplateName=template_name)
    )
    assert code_after == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected ApprovalRuleTemplateDoesNotExistException after delete, got {code_after!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {template_name}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
    )
    assert message_after == expected_message, (
        f"expected message {expected_message!r}, got {message_after!r}"
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


def _create_repo(ctx) -> str:
    cc: Any = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-repo-")
    cc.create_repository(repositoryName=name, tags={"sim2real": "art-diu"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))
    return name


def _create_template(ctx) -> str:
    cc: Any = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-art-")
    content = json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}],
        }
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=name, approvalRuleTemplateContent=content
    )

    def _cleanup():
        try:
            cc.delete_approval_rule_template(approvalRuleTemplateName=name)
        except cc.exceptions.ApprovalRuleTemplateDoesNotExistException:
            pass

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
