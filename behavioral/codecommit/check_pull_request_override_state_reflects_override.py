"""pull-request-override-state-reflects-override."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pull-request-override-state-reflects-override"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OverridePullRequestApprovalRules flips GetPullRequestOverrideState and unblocks
    EvaluatePullRequestApprovalRules' approved result."""
    cc = ctx.client("codecommit")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]

    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccoverride"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"base\n",
        filePath="readme.md",
        commitMessage="base",
    )
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base["commitId"])
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature change\n",
        filePath="readme.md",
        parentCommitId=base["commitId"],
        commitMessage="feature change",
    )

    pr = cc.create_pull_request(
        title=ctx.unique_name("sim2real-pr-"),
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
    ctx.on_cleanup(lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED"))

    rule_name = ctx.unique_name("sim2real-rule-")
    rule_content = (
        '{"Version":"2018-11-08","Statements":[{"Type":"Approvers",'
        f'"NumberOfApprovalsNeeded":1,"ApprovalPoolMembers":["{caller_arn}"]}}]}}'
    )
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName=rule_name, approvalRuleContent=rule_content
    )

    # The rule can never be satisfied here: the caller is the PR author and CodeCommit forbids
    # authors from approving their own pull request, regardless of approval-pool membership.
    pre_override = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert pre_override["approved"] is False, (
        f"expected approved=False before override (author cannot self-approve), got "
        f"{pre_override['approved']!r}"
    )
    assert pre_override["overridden"] is False, (
        f"expected overridden=False before any override call, got {pre_override['overridden']!r}"
    )
    assert rule_name in pre_override["approvalRulesNotSatisfied"], (
        f"expected {rule_name!r} in approvalRulesNotSatisfied before override, got "
        f"{pre_override['approvalRulesNotSatisfied']!r}"
    )

    pre_state = cc.get_pull_request_override_state(pullRequestId=pr_id, revisionId=revision_id)
    assert pre_state["overridden"] is False, (
        f"expected GetPullRequestOverrideState overridden=False before any override call, got "
        f"{pre_state['overridden']!r}"
    )

    cc.override_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id, overrideStatus="OVERRIDE"
    )

    post_state = cc.get_pull_request_override_state(pullRequestId=pr_id, revisionId=revision_id)
    assert post_state["overridden"] is True, (
        f"expected overridden=True after OVERRIDE, got {post_state['overridden']!r}"
    )
    assert post_state["overrider"] == caller_arn, (
        f"expected overrider={caller_arn!r}, got {post_state['overrider']!r}"
    )

    post_override = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    # Overriding bypasses the rule requirement for merge purposes, but it does not retroactively
    # mark the (still-unsatisfied) rule as approved -- "approved" tracks actual rule satisfaction,
    # "overridden" is the separate bypass flag that unblocks merging.
    assert post_override["overridden"] is True, (
        f"expected overridden=True in the post-override evaluation, got "
        f"{post_override['overridden']!r}"
    )
    assert post_override["approved"] is False, (
        f"expected approved=False to persist after override (override does not satisfy the "
        f"rule), got {post_override['approved']!r}"
    )
    assert rule_name in post_override["approvalRulesNotSatisfied"], (
        f"expected {rule_name!r} to remain in approvalRulesNotSatisfied after override, got "
        f"{post_override['approvalRulesNotSatisfied']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
