"""approval-rule-template-association-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "approval-rule-template-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["codecommit"]

_TEMPLATE_CONTENT = json.dumps(
    {
        "Version": "2018-11-08",
        "DestinationReferences": ["refs/heads/main"],
        "Statements": [{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An approval rule template associated with a repository is listed with it and cannot be deleted
    (ApprovalRuleTemplateInUseException); after disassociation the delete succeeds and the template is
    gone (ApprovalRuleTemplateDoesNotExistException)."""
    codecommit = ctx.client("codecommit")

    template_name = ctx.unique_name("sim2real-behav-art-")
    codecommit.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=_TEMPLATE_CONTENT,
    )
    ctx.on_cleanup(lambda: codecommit.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    codecommit.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    associated = codecommit.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name in associated, (
        f"expected {repo_name!r} in associated repos {associated!r} after associate"
    )

    # While still associated, deletion is rejected — not merely disassociated first
    # out of convenience.
    in_use_code, in_use_message = _error(
        lambda: codecommit.delete_approval_rule_template(approvalRuleTemplateName=template_name)
    )
    assert in_use_code == "ApprovalRuleTemplateInUseException", (
        f"expected ApprovalRuleTemplateInUseException deleting a template still "
        f"associated with {repo_name!r}, got {in_use_code!r}"
    )
    expected_message = (
        "The approval rule template cannot be deleted because it is associated "
        "with one or more repositories. You cannot delete a template if it is "
        "associated with a repository. Disassociate the template from all "
        "repositories in your AWS account, and then try again."
    )
    assert in_use_message == expected_message, (
        f"expected message {expected_message!r}, got {in_use_message!r}"
    )
    still_there = codecommit.get_approval_rule_template(approvalRuleTemplateName=template_name)[
        "approvalRuleTemplate"
    ]
    assert still_there["approvalRuleTemplateName"] == template_name, (
        f"expected {template_name!r} to survive the rejected delete, got {still_there!r}"
    )

    codecommit.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    remaining = codecommit.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name not in remaining, (
        f"expected {repo_name!r} removed from associated repos {remaining!r} after disassociate"
    )

    # Now that no repository references it, the identical delete call succeeds.
    codecommit.delete_approval_rule_template(approvalRuleTemplateName=template_name)

    code, message = _error(lambda: codecommit.get_approval_rule_template(approvalRuleTemplateName=template_name))
    assert code == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected ApprovalRuleTemplateDoesNotExistException reading a deleted template, got {code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {template_name}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
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
