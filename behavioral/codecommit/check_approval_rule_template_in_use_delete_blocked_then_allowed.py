"""approval-rule-template-in-use-delete-blocked-then-allowed."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "approval-rule-template-in-use-delete-blocked-then-allowed"
GROUP = "state-machine"
SERVICES = ["codecommit"]

_TEMPLATE_CONTENT = json.dumps(
    {
        "Version": "2018-11-08",
        "DestinationReferences": ["refs/heads/main"],
        "Statements": [{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a template still associated with a repository fails with
    ApprovalRuleTemplateInUseException, the template and its association survive the
    rejected attempt, and deletion succeeds only after disassociation."""
    codecommit = ctx.client("codecommit")

    template_name = ctx.unique_name("sim2real-behav-art-")
    codecommit.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=_TEMPLATE_CONTENT,
    )
    ctx.on_cleanup(lambda: codecommit.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name, tags={"sim2real": "ccartblk"})
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    codecommit.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )

    # Break exactly one thing: try to delete a template that is still in use.
    code, message = _error(lambda: codecommit.delete_approval_rule_template(approvalRuleTemplateName=template_name))
    assert code == "ApprovalRuleTemplateInUseException", (
        f"deleting a template still associated with a repository must be refused with "
        f"'ApprovalRuleTemplateInUseException'; got {code!r}"
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

    # Effect absent: the template still exists and the association still holds.
    still_exists = codecommit.get_approval_rule_template(approvalRuleTemplateName=template_name)
    assert still_exists["approvalRuleTemplate"]["approvalRuleTemplateName"] == template_name, (
        f"the refused delete must leave the template intact; GetApprovalRuleTemplate returned "
        f"{still_exists['approvalRuleTemplate']!r}"
    )
    still_associated = codecommit.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name in still_associated, (
        f"the refused delete must leave the association intact; expected {repo_name!r} in "
        f"{still_associated!r}"
    )

    # Positive control: after removing the one blocking condition, the same delete
    # call that was just rejected now succeeds.
    codecommit.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    codecommit.delete_approval_rule_template(approvalRuleTemplateName=template_name)

    gone_code, gone_message = _error(lambda: codecommit.get_approval_rule_template(approvalRuleTemplateName=template_name))
    assert gone_code == "ApprovalRuleTemplateDoesNotExistException", (
        f"after the control delete the template must be gone; GetApprovalRuleTemplate raised "
        f"{gone_code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {template_name}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
    )
    assert gone_message == expected_message, (
        f"expected message {expected_message!r}, got {gone_message!r}"
    )

    # Mutation on the dead id also fails: disassociating an already-deleted template is not a
    # silent no-op.
    dead_code, dead_message = _error(lambda: codecommit.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    ))
    assert dead_code == "ApprovalRuleTemplateDoesNotExistException", (
        f"disassociating a deleted template must fail with "
        f"'ApprovalRuleTemplateDoesNotExistException'; got {dead_code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {template_name}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
    )
    assert dead_message == expected_message, (
        f"expected message {expected_message!r}, got {dead_message!r}"
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
