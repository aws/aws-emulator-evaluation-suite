"""delete-template-derived-approval-rule-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-template-derived-approval-rule-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePullRequestApprovalRule on a template-derived rule raises
    CannotDeleteApprovalRuleFromTemplateException and leaves the rule attached; a rule added
    directly to the pull request deletes normally."""
    cc = ctx.client("codecommit")
    template_name = ctx.unique_name("sim2real-cc-template-")
    template_content = (
        '{"Version": "2018-11-08", "Statements": '
        '[{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}]}'
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=template_content,
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(
        approvalRuleTemplateName=template_name,
    ))

    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-template-derived-rule"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name,
    )
    ctx.on_cleanup(lambda: cc.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name,
    ))

    commit1 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="initial commit",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello"}],
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=commit1)
    cc.create_commit(
        repositoryName=repo_name,
        branchName="feature",
        parentCommitId=commit1,
        putFiles=[{"filePath": "feature.txt", "fileContent": b"feature"}],
    )

    pr_id = cc.create_pull_request(
        title=ctx.unique_name("sim2real-pr-"),
        targets=[{
            "repositoryName": repo_name,
            "sourceReference": "feature",
            "destinationReference": "main",
        }],
        clientRequestToken=ctx.unique_name("sim2real-token-"),
    )["pullRequest"]["pullRequestId"]
    ctx.on_cleanup(lambda: cc.update_pull_request_status(
        pullRequestId=pr_id, pullRequestStatus="CLOSED",
    ))

    rules = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    template_rules = [
        r for r in rules
        if r.get("originApprovalRuleTemplate", {}).get("approvalRuleTemplateName") == template_name
    ]
    assert len(template_rules) == 1, f"expected exactly one template-derived rule, got {rules}"
    template_rule_name = template_rules[0]["approvalRuleName"]

    code, message = _error(lambda: cc.delete_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName=template_rule_name,
    ))
    assert code == "CannotDeleteApprovalRuleFromTemplateException", f"unexpected code: {code}"
    expected = (
        "The approval rule cannot be deleted from the pull request because it was created by an "
        "approval rule template and automatically applied to the pull request."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    still_there_names = [r["approvalRuleName"] for r in still_there]
    assert template_rule_name in still_there_names, (
        f"expected template-derived rule {template_rule_name!r} to remain attached, "
        f"but pull request approval rules are now {still_there_names!r}"
    )

    # positive control: a rule added directly to the pull request deletes cleanly
    manual_rule_name = "manual-rule"
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName=manual_rule_name, approvalRuleContent=template_content,
    )
    cc.delete_pull_request_approval_rule(pullRequestId=pr_id, approvalRuleName=manual_rule_name)
    after = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    after_names = [r["approvalRuleName"] for r in after]
    assert manual_rule_name not in after_names, (
        f"expected manually-added rule {manual_rule_name!r} to be gone after delete, "
        f"but pull request approval rules are still {after_names!r}"
    )



def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
