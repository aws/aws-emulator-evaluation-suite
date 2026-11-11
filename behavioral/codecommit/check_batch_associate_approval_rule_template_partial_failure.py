"""batch-associate-approval-rule-template-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-associate-approval-rule-template-partial-failure"
GROUP = "error-semantics"
SERVICES = ["codecommit"]

_TEMPLATE_CONTENT = (
    '{"Version": "2018-11-08","Statements": '
    '[{"Type": "Approvers","NumberOfApprovalsNeeded": 1}]}'
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchAssociateApprovalRuleTemplateWithRepositories with one valid and one missing
    repository associates the valid one and reports a per-repository error for the other,
    rather than failing the whole batch or dropping the valid association."""
    cc = ctx.client("codecommit")
    template_name = ctx.unique_name("sim2real-behav-baartp-")
    repo_name = ctx.unique_name("sim2real-behav-baartp-repo-")
    missing_repo_name = ctx.unique_name("sim2real-behav-baartp-missing-")

    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=_TEMPLATE_CONTENT
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)
        )
    )
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "baartp"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: cc.disassociate_approval_rule_template_from_repository(
                approvalRuleTemplateName=template_name, repositoryName=repo_name
            )
        )
    )

    result = cc.batch_associate_approval_rule_template_with_repositories(
        approvalRuleTemplateName=template_name,
        repositoryNames=[repo_name, missing_repo_name],
    )

    assert result["associatedRepositoryNames"] == [repo_name], result["associatedRepositoryNames"]
    assert len(result["errors"]) == 1, result["errors"]
    error_entry = result["errors"][0]
    assert error_entry["repositoryName"] == missing_repo_name, error_entry
    assert error_entry["errorCode"] == "RepositoryDoesNotExistException", error_entry["errorCode"]

    # The valid repository is really associated, not just reported as such.
    associated = cc.list_repositories_for_approval_rule_template(
        approvalRuleTemplateName=template_name
    )["repositoryNames"]
    assert repo_name in associated, associated
    assert missing_repo_name not in associated, associated


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
