"""approval-rule-content-required-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "approval-rule-content-required-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePullRequestApprovalRule with an empty approvalRuleContent raises
    InvalidApprovalRuleContentException and attaches no rule, while a valid rule attaches."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccarcr"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

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
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="feature work",
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

    # ApprovalRuleContent has a documented min length of 1, so botocore's client-side
    # length validation would otherwise raise ParamValidationError locally before the
    # request is sent; a client with validation off observes the service's own error class.
    unvalidated = ctx.client("codecommit", config=Config(parameter_validation=False))
    code, message = _error(lambda: unvalidated.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName="empty-content-rule", approvalRuleContent="",
    ))
    assert code == "InvalidApprovalRuleContentException", f"unexpected code: {code}"
    expected_message = (
        "Content for an approval rule is required, but the content of the "
        "approval rule was either empty or null."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    rules = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    assert not any(r["approvalRuleName"] == "empty-content-rule" for r in rules), (
        f"expected no rule named 'empty-content-rule' to be attached, found: {rules}"
    )

    # positive control: valid content succeeds and attaches the rule
    content = (
        '{"Version": "2018-11-08", "Statements": '
        '[{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}]}'
    )
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName="valid-rule", approvalRuleContent=content,
    )
    rules2 = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    assert any(r["approvalRuleName"] == "valid-rule" for r in rules2), (
        f"expected 'valid-rule' to be attached after a valid create call, found: {rules2}"
    )


def _error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(
        f"real AWS rejects create_pull_request_approval_rule with empty content, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
