"""cannot-delete-approval-rule-from-template-blocked."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cannot-delete-approval-rule-from-template-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]

_TEMPLATE_CONTENT = (
    '{"Version": "2018-11-08","Statements": '
    '[{"Type": "Approvers","NumberOfApprovalsNeeded": 1}]}'
)
_DIRECT_RULE_CONTENT = (
    '{"Version": "2018-11-08","Statements": '
    '[{"Type": "Approvers","NumberOfApprovalsNeeded": 1}]}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePullRequestApprovalRule on a rule that came from an associated approval rule template
    is rejected with CannotDeleteApprovalRuleFromTemplateException, while a rule created directly
    on the pull request is deleted normally."""
    cc = ctx.client("codecommit")
    template_name = ctx.unique_name("sim2real-behav-cdarft-")
    repo_name = ctx.unique_name("sim2real-behav-cdarft-repo-")

    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=_TEMPLATE_CONTENT
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name)
        )
    )

    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cdarft"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    # Associate *before* creating the pull request so the template rule is generated
    # automatically for it.
    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: cc.disassociate_approval_rule_template_from_repository(
                approvalRuleTemplateName=template_name, repositoryName=repo_name
            )
        )
    )

    put1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"init", filePath="README.md"
    )
    base_commit = put1["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    targets = [
        {"repositoryName": repo_name, "sourceReference": "feature", "destinationReference": "main"}
    ]
    created = cc.create_pull_request(title="template-rule-pr", targets=targets)
    pr_id = created["pullRequest"]["pullRequestId"]
    ctx.on_cleanup(
        lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
    )

    template_rule = _poll_for_template_rule(ctx, cc, pr_id, template_name)
    assert template_rule is not None, "template-originated approval rule never appeared on the PR"
    template_rule_name = template_rule["approvalRuleName"]

    code, message = _error(
        lambda: cc.delete_pull_request_approval_rule(
            pullRequestId=pr_id, approvalRuleName=template_rule_name
        )
    )
    assert code == "CannotDeleteApprovalRuleFromTemplateException", (
        f"expected CannotDeleteApprovalRuleFromTemplateException, got {code!r}"
    )
    expected_message = (
        "The approval rule cannot be deleted from the pull request because it "
        "was created by an approval rule template and automatically applied to "
        "the pull request."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the template-originated rule is still on the pull request.
    still_there = [
        r
        for r in cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
        if r["approvalRuleName"] == template_rule_name
    ]
    assert len(still_there) == 1, (
        f"expected the template-derived rule to remain attached, found {len(still_there)} matches"
    )

    # Positive control: a rule created directly on the PR can be deleted normally.
    direct_name = ctx.unique_name("direct-rule-")
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName=direct_name, approvalRuleContent=_DIRECT_RULE_CONTENT
    )
    cc.delete_pull_request_approval_rule(pullRequestId=pr_id, approvalRuleName=direct_name)
    remaining = [
        r
        for r in cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
        if r["approvalRuleName"] == direct_name
    ]
    assert remaining == [], f"expected the directly-created rule to be gone, found {remaining!r}"


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


def _poll_for_template_rule(ctx, cc, pr_id, template_name, timeout_s=20.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        rules = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
        for rule in rules:
            origin = rule.get("originApprovalRuleTemplate")
            if origin and origin.get("approvalRuleTemplateName") == template_name:
                return rule
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
