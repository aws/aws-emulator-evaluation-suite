"""e2e-pull-request-approval-and-merge-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pull-request-approval-and-merge-flow"
GROUP = "e2e"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full PR lifecycle: open a PR with an approval rule, approve it as a second IAM identity
    (authors cannot self-approve), squash-merge, and confirm the destination head advanced
    and the PR ends up MERGED and CLOSED."""
    cc = ctx.client("codecommit")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    # Initial commit creates the (empty) repo's first branch + default branch.
    put1 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"hello world\n",
        filePath="README.md",
        commitMessage="initial commit",
    )
    initial_commit_id = put1["commitId"]
    cc.update_default_branch(repositoryName=repo_name, defaultBranchName="main")

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=initial_commit_id)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature contents\n",
        filePath="feature.txt",
        commitMessage="feature commit",
        parentCommitId=initial_commit_id,
    )

    # A second identity is required: on real AWS a pull request's own author cannot
    # approve it (PullRequestCannotBeApprovedByAuthorException).
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-cc-approver-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "approve-pr"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "codecommit:GetPullRequest",
                    "codecommit:UpdatePullRequestApprovalState",
                    "codecommit:GetPullRequestApprovalStates",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    session_creds = _assume_role_with_retry(sts, role_arn, ctx.unique_name("sess-"))
    approver_cc = _client_from_creds(ctx, "codecommit", session_creds)

    pr = cc.create_pull_request(
        title="merge feature into main",
        description="sim2real behavioral check PR",
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

    rule_content = {
        "Version": "2018-11-08",
        "Statements": [
            {
                "Type": "Approvers",
                "NumberOfApprovalsNeeded": 1,
                "ApprovalPoolMembers": [f"arn:aws:sts::{account_id}:assumed-role/{role_name}/*"],
            }
        ],
    }
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id,
        approvalRuleName=ctx.unique_name("rule-"),
        approvalRuleContent=json.dumps(rule_content),
    )

    # Merging before the rule is satisfied must be rejected.
    code, message = _error(
        lambda: cc.merge_pull_request_by_squash(pullRequestId=pr_id, repositoryName=repo_name)
    )
    assert code == "PullRequestApprovalRulesNotSatisfiedException", (
        f"merging with an unsatisfied approval rule was expected to be refused with "
        f"PullRequestApprovalRulesNotSatisfiedException, got {code!r}"
    )
    expected = (
        "You cannot merge the pull request because the requirements for one or more approval "
        "rules have not been met. For details about the approval rules that still have "
        "requirements, use EvaluatePullRequestApprovalRules."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    unmerged_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert unmerged_pr["pullRequestStatus"] == "OPEN", (
        f"the refused merge must leave the PR OPEN, got {unmerged_pr['pullRequestStatus']!r}"
    )
    unmerged_branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert unmerged_branch["commitId"] == initial_commit_id, (
        f"the refused merge must leave main's head at {initial_commit_id!r}, "
        f"got {unmerged_branch['commitId']!r}"
    )

    approver_cc.update_pull_request_approval_state(
        pullRequestId=pr_id, revisionId=revision_id, approvalState="APPROVE"
    )
    approvals = cc.get_pull_request_approval_states(pullRequestId=pr_id, revisionId=revision_id)[
        "approvals"
    ]
    assert len(approvals) == 1 and approvals[0]["approvalState"] == "APPROVE", (
        f"expected exactly one APPROVE approval from the second identity, got {approvals!r}"
    )

    evaluation = cc.evaluate_pull_request_approval_rules(pullRequestId=pr_id, revisionId=revision_id)[
        "evaluation"
    ]
    assert evaluation["approved"] is True, (
        f"expected the approval rule evaluation to report approved=True after the approve, "
        f"got {evaluation!r}"
    )

    merge_result = cc.merge_pull_request_by_squash(pullRequestId=pr_id, repositoryName=repo_name)
    assert merge_result["pullRequest"]["pullRequestStatus"] == "CLOSED", (
        f"expected the identical merge call to succeed once approved, got status "
        f"{merge_result['pullRequest']['pullRequestStatus']!r}"
    )

    final_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert final_pr["pullRequestStatus"] == "CLOSED", (
        f"an independent GetPullRequest read expected CLOSED, got {final_pr['pullRequestStatus']!r}"
    )

    main_branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert main_branch["commitId"] != initial_commit_id, (
        "main's head commit did not advance after the squash merge"
    )
    merged_commit = cc.get_commit(repositoryName=repo_name, commitId=main_branch["commitId"])["commit"]
    assert initial_commit_id in merged_commit["parents"], (
        f"expected the pre-merge commit {initial_commit_id!r} among the merge commit's parents, "
        f"got {merged_commit['parents']!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _assume_role_with_retry(
    sts_client: Any, role_arn: str, session_name: str, timeout_s: float = 30.0, interval_s: float = 2.0
) -> dict[str, str]:
    """IAM roles are eventually consistent; retry AssumeRole until it takes effect."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException"):
                raise
            time.sleep(interval_s)
    raise AssertionError(f"AssumeRole never succeeded within {timeout_s}s: {last_exc}")


def _client_from_creds(ctx: Any, service: str, creds: dict[str, str]):
    """A client for ``service`` that signs as the assumed-role session, against the same target."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
