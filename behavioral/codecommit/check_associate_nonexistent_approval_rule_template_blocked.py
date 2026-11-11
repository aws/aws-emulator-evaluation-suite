"""associate-nonexistent-approval-rule-template-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-nonexistent-approval-rule-template-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a never-created approval rule template with a repository raises
    ApprovalRuleTemplateDoesNotExistException and adds no association; once a template of that name
    exists the identical call associates it."""
    codecommit = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name, tags={"sim2real": "behav"})
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    ghost_template = ctx.unique_name("sim2real-behav-ghost-template-")
    code, message = _error(
        lambda: codecommit.associate_approval_rule_template_with_repository(
            approvalRuleTemplateName=ghost_template, repositoryName=repo_name
        )
    )
    assert code == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected ApprovalRuleTemplateDoesNotExistException, got {code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {ghost_template}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: no association was recorded for the (nonexistent) template.
    associated = codecommit.list_associated_approval_rule_templates_for_repository(
        repositoryName=repo_name
    )["approvalRuleTemplateNames"]
    assert ghost_template not in associated, f"ghost template leaked into {associated!r}"
    assert associated == [], f"expected no associations, got {associated!r}"

    # Restore: back the identical name with a real template, then repeat the identical
    # call. This proves the earlier rejection tracked the template's existence, not its
    # name -- a target that hardcoded rejection for this name would fail here.
    content = (
        '{"Version":"2018-11-08","Statements":[{"Type":"Approvers",'
        '"NumberOfApprovalsNeeded":1}]}'
    )
    codecommit.create_approval_rule_template(
        approvalRuleTemplateName=ghost_template, approvalRuleTemplateContent=content
    )
    ctx.on_cleanup(
        lambda: codecommit.delete_approval_rule_template(
            approvalRuleTemplateName=ghost_template
        )
    )

    codecommit.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=ghost_template, repositoryName=repo_name
    )
    ctx.on_cleanup(
        lambda: codecommit.disassociate_approval_rule_template_from_repository(
            approvalRuleTemplateName=ghost_template, repositoryName=repo_name
        )
    )
    associated_after = codecommit.list_associated_approval_rule_templates_for_repository(
        repositoryName=repo_name
    )["approvalRuleTemplateNames"]
    assert associated_after == [ghost_template], (
        f"expected [{ghost_template!r}], got {associated_after!r}"
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
