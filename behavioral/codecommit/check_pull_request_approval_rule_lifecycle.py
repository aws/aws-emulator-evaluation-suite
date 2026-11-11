"""pull-request-approval-rule-lifecycle."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pull-request-approval-rule-lifecycle"
GROUP = "state-machine"
SERVICES = ["codecommit"]


def _rule_content(num_approvals: int) -> str:
    return json.dumps(
        {
            "Version": "2018-11-08",
            "Statements": [{"Type": "Approvers", "NumberOfApprovalsNeeded": num_approvals}],
        }
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePullRequestApprovalRule adds a rule visible on the PR; Update changes it; Delete removes it."""
    cc = ctx.client("codecommit")
    repo_name, pr_id = _create_repo_and_open_pr(ctx)
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    initial_content = _rule_content(1)

    created_rule = cc.create_pull_request_approval_rule(
        pullRequestId=pr_id,
        approvalRuleName=rule_name,
        approvalRuleContent=initial_content,
    )["approvalRule"]
    rule_id = created_rule["approvalRuleId"]
    sha_before = created_rule["ruleContentSha256"]

    pr_after_create = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    rules_by_name = {r["approvalRuleName"]: r for r in pr_after_create["approvalRules"]}
    assert rule_name in rules_by_name, f"expected {rule_name!r} in {sorted(rules_by_name)}"
    assert rules_by_name[rule_name]["approvalRuleId"] == rule_id, (
        f"expected approvalRuleId {rule_id!r}, got {rules_by_name[rule_name]['approvalRuleId']!r}"
    )
    assert json.loads(rules_by_name[rule_name]["approvalRuleContent"]) == json.loads(initial_content), (
        f"expected content {initial_content!r}, got {rules_by_name[rule_name]['approvalRuleContent']!r}"
    )

    updated_content = _rule_content(2)
    updated_rule = cc.update_pull_request_approval_rule_content(
        pullRequestId=pr_id,
        approvalRuleName=rule_name,
        newRuleContent=updated_content,
    )["approvalRule"]
    assert json.loads(updated_rule["approvalRuleContent"]) == json.loads(updated_content), (
        f"expected updated content {updated_content!r}, got {updated_rule['approvalRuleContent']!r}"
    )
    assert updated_rule["ruleContentSha256"] != sha_before, (
        f"expected ruleContentSha256 to change from {sha_before!r} after update"
    )

    pr_after_update = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    rules_by_name = {r["approvalRuleName"]: r for r in pr_after_update["approvalRules"]}
    assert json.loads(rules_by_name[rule_name]["approvalRuleContent"]) == json.loads(updated_content), (
        f"expected updated content {updated_content!r} on independent read, "
        f"got {rules_by_name[rule_name]['approvalRuleContent']!r}"
    )

    cc.delete_pull_request_approval_rule(pullRequestId=pr_id, approvalRuleName=rule_name)

    pr_after_delete = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    remaining_names = {r["approvalRuleName"] for r in pr_after_delete["approvalRules"]}
    assert rule_name not in remaining_names, (
        f"expected {rule_name!r} gone from approvalRules, still present in {sorted(remaining_names)}"
    )

    code, message = _error(lambda: cc.update_pull_request_approval_rule_content(
        pullRequestId=pr_id,
        approvalRuleName=rule_name,
        newRuleContent=_rule_content(3),
    ))
    assert code == "ApprovalRuleDoesNotExistException", (
        f"expected ApprovalRuleDoesNotExistException updating a deleted rule, got {code!r}"
    )
    assert message == (
        f"No approval rule exists with the following name: {rule_name}. Verify that you have "
        "provided the correct name, and that you have provided the ID of the pull request "
        "where this rule has been applied."
    ), message


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _create_repo_and_open_pr(ctx) -> tuple[str, str]:
    cc: Any = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "pralc"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    initial_commit_id = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello world"}],
        commitMessage="initial commit",
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=initial_commit_id)
    cc.create_commit(
        repositoryName=repo_name,
        branchName="feature",
        parentCommitId=initial_commit_id,
        putFiles=[{"filePath": "feature.txt", "fileContent": b"feature content"}],
        commitMessage="feature commit",
    )

    pr = cc.create_pull_request(
        title=ctx.unique_name("sim2real-behav-pr-"),
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]

    def _cleanup():
        try:
            cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "EncryptionKeyNotFoundException",
                "PullRequestDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    return repo_name, pr_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
