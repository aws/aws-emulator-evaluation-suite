"""merge-rejected-when-approval-rules-not-satisfied."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "merge-rejected-when-approval-rules-not-satisfied"
GROUP = "state-machine"
SERVICES = ["codecommit"]

_RULE_CONTENT = (
    '{"Version":"2018-11-08","Statements":'
    '[{"Type":"Approvers","NumberOfApprovalsNeeded":1}]}'
)


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A fast-forward merge is rejected with PullRequestApprovalRulesNotSatisfiedException
    while an approval rule on the PR remains unsatisfied, the destination branch is left
    untouched, and the exact same merge succeeds once the rule is overridden."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-mergegate-repo-")

    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccmergegate"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    main_head = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"root\n",
        filePath="root.txt",
        commitMessage="initial commit",
        name="sim2real",
        email="sim2real@example.com",
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=main_head)
    feature_head = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"change\n",
        filePath="change.txt",
        parentCommitId=main_head,
        commitMessage="feature change",
        name="sim2real",
        email="sim2real@example.com",
    )["commitId"]
    assert feature_head != main_head, (
        f"the feature commit must differ from the main commit; got {feature_head!r} == "
        f"{main_head!r}"
    )

    pr = cc.create_pull_request(
        title="Feature PR",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]
    revision_id = pr["revisionId"]

    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id,
        approvalRuleName=ctx.unique_name("sim2real-gate-rule-"),
        approvalRuleContent=_RULE_CONTENT,
    )

    # Break exactly one thing: attempt to merge before the rule is satisfied.
    code, message = _error(
        lambda: cc.merge_pull_request_by_fast_forward(
            pullRequestId=pr_id, repositoryName=repo_name
        )
    )
    assert code == "PullRequestApprovalRulesNotSatisfiedException", (
        f"merging with an unsatisfied approval rule raised {code!r}, expected "
        "PullRequestApprovalRulesNotSatisfiedException"
    )
    assert message == (
        "You cannot merge the pull request because the requirements for one or more approval "
        "rules have not been met. For details about the approval rules that still have "
        "requirements, use EvaluatePullRequestApprovalRules."
    ), message

    # Effect absent: destination branch untouched, PR still OPEN.
    main_branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert main_branch["commitId"] == main_head, (
        f"the refused merge advanced main from {main_head!r} to {main_branch['commitId']!r}"
    )
    still_open_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert still_open_pr["pullRequestStatus"] == "OPEN", (
        f"the refused merge changed the pull request status to "
        f"{still_open_pr['pullRequestStatus']!r}, expected OPEN"
    )

    # Positive control in the same file: satisfy the rule (via override) and the
    # identical merge now succeeds, advancing the destination branch.
    cc.override_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id, overrideStatus="OVERRIDE"
    )
    merged_pr = cc.merge_pull_request_by_fast_forward(
        pullRequestId=pr_id, repositoryName=repo_name
    )["pullRequest"]
    assert merged_pr["pullRequestStatus"] == "CLOSED", (
        f"the merge after overriding the rule left the pull request "
        f"{merged_pr['pullRequestStatus']!r}, expected CLOSED"
    )

    main_branch_after = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert main_branch_after["commitId"] == feature_head, (
        f"after the override merge main is {main_branch_after['commitId']!r}, expected the "
        f"feature commit {feature_head!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
