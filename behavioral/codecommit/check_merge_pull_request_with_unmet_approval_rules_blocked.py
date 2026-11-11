"""merge-pull-request-with-unmet-approval-rules-blocked."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-pull-request-with-unmet-approval-rules-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Merging a pull request with an unsatisfied approval rule raises
    PullRequestApprovalRulesNotSatisfiedException and leaves it OPEN; after an override the identical
    merge closes it, and a rule-free sibling merges."""
    codecommit = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    seed = codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=base64.b64encode(b"seed content").decode(),
        filePath="README.md",
        commitMessage="seed commit",
    )
    main_tip = seed["commitId"]

    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # --- Blocked PR: approval rule requires an approver who will never show up. ---
    codecommit.create_branch(
        repositoryName=repo_name, branchName="feature-blocked", commitId=main_tip
    )
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="feature-blocked",
        fileContent=base64.b64encode(b"blocked change").decode(),
        filePath="blocked.txt",
        parentCommitId=main_tip,
        commitMessage="feature change for blocked PR",
    )
    pr_blocked = codecommit.create_pull_request(
        title="blocked PR",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature-blocked",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_blocked_id = pr_blocked["pullRequestId"]
    ctx.on_cleanup(lambda: _safe_close(codecommit, pr_blocked_id))

    approval_rule_content = (
        '{"Version":"2018-11-08","Statements":[{"Type":"Approvers",'
        '"NumberOfApprovalsNeeded":1,"ApprovalPoolMembers":'
        f'["arn:aws:iam::{account_id}:user/sim2real-nobody-will-ever-approve"]}}]}}'
    )
    codecommit.create_pull_request_approval_rule(
        pullRequestId=pr_blocked_id,
        approvalRuleName="require-one-approval",
        approvalRuleContent=approval_rule_content,
    )

    code, message = _error(
        lambda: codecommit.merge_pull_request_by_three_way(
            pullRequestId=pr_blocked_id, repositoryName=repo_name
        )
    )
    assert code == "PullRequestApprovalRulesNotSatisfiedException", code
    assert message == (
        "You cannot merge the pull request because the requirements for one or more approval "
        "rules have not been met. For details about the approval rules that still have "
        "requirements, use EvaluatePullRequestApprovalRules."
    ), message

    # Effect absent: the PR is still OPEN and main's tip is unchanged.
    still_open = codecommit.get_pull_request(pullRequestId=pr_blocked_id)["pullRequest"]
    assert still_open["pullRequestStatus"] == "OPEN"
    assert codecommit.get_branch(repositoryName=repo_name, branchName="main")["branch"][
        "commitId"
    ] == main_tip

    # --- Restore: overriding the rule makes the identical merge call succeed. ---
    blocked_revision = codecommit.get_pull_request(pullRequestId=pr_blocked_id)[
        "pullRequest"
    ]["revisionId"]
    codecommit.override_pull_request_approval_rules(
        pullRequestId=pr_blocked_id, revisionId=blocked_revision, overrideStatus="OVERRIDE"
    )
    restored_merge = codecommit.merge_pull_request_by_three_way(
        pullRequestId=pr_blocked_id, repositoryName=repo_name
    )["pullRequest"]
    assert restored_merge["pullRequestStatus"] == "CLOSED", restored_merge["pullRequestStatus"]
    assert restored_merge["pullRequestTargets"][0]["mergeMetadata"]["isMerged"] is True, (
        restored_merge["pullRequestTargets"][0]["mergeMetadata"]
    )
    restored_tip = codecommit.get_branch(repositoryName=repo_name, branchName="main")[
        "branch"
    ]["commitId"]
    assert restored_tip != main_tip, "overriding the rule did not let the merge advance main"

    # --- Positive control: a PR with no approval rule merges cleanly. ---
    codecommit.create_branch(
        repositoryName=repo_name, branchName="feature-clean", commitId=main_tip
    )
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="feature-clean",
        fileContent=base64.b64encode(b"clean change").decode(),
        filePath="clean.txt",
        parentCommitId=main_tip,
        commitMessage="feature change for clean PR",
    )
    pr_clean_id = codecommit.create_pull_request(
        title="clean PR",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature-clean",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]["pullRequestId"]

    merge_result = codecommit.merge_pull_request_by_three_way(
        pullRequestId=pr_clean_id, repositoryName=repo_name
    )
    assert merge_result["pullRequest"]["pullRequestStatus"] == "CLOSED"
    merged_target = merge_result["pullRequest"]["pullRequestTargets"][0]
    assert merged_target["mergeMetadata"]["isMerged"] is True
    new_main_tip = codecommit.get_branch(repositoryName=repo_name, branchName="main")[
        "branch"
    ]["commitId"]
    assert new_main_tip != main_tip


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _safe_close(codecommit, pull_request_id):
    """Cleanup-only: the check's own restore leg may already have merged (and thus
    closed) this pull request, so closing it again is a no-op, not a defect."""
    try:
        codecommit.update_pull_request_status(
            pullRequestId=pull_request_id, pullRequestStatus="CLOSED"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "PullRequestAlreadyClosedException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
