"""e2e-merge-pull-request-approval-rules-not-satisfied-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-merge-pull-request-approval-rules-not-satisfied-rejected"
GROUP = "e2e"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Merging a PR with an unsatisfied approval rule raises
    PullRequestApprovalRulesNotSatisfiedException and leaves the branch and OPEN status as is;
    a rule-free PR merges first, and the same merge succeeds once a second identity approves."""
    cc = ctx.client("codecommit")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cceprns"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    initial_commit_id = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"hello world\n",
        filePath="README.md",
        commitMessage="initial commit",
    )["commitId"]
    cc.update_default_branch(repositoryName=repo_name, defaultBranchName="main")

    # --- positive control: a PR with no approval rule merges cleanly, before the negative
    #     scenario exists at all ---
    cc.create_branch(repositoryName=repo_name, branchName="control", commitId=initial_commit_id)
    cc.put_file(
        repositoryName=repo_name,
        branchName="control",
        fileContent=b"control contents\n",
        filePath="control.txt",
        commitMessage="control commit",
        parentCommitId=initial_commit_id,
    )
    control_pr_id = cc.create_pull_request(
        title="control pr with no approval rule",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "control",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]["pullRequestId"]
    control_merge = cc.merge_pull_request_by_squash(
        pullRequestId=control_pr_id, repositoryName=repo_name
    )
    assert control_merge["pullRequest"]["pullRequestStatus"] == "CLOSED", (
        "positive control: a pull request with no approval rule must merge cleanly, got "
        f"status {control_merge['pullRequest']['pullRequestStatus']!r}"
    )
    baseline_commit_id = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"][
        "commitId"
    ]
    assert baseline_commit_id != initial_commit_id, (
        "positive control merge did not advance main"
    )

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=baseline_commit_id)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature contents\n",
        filePath="feature.txt",
        commitMessage="feature commit",
        parentCommitId=baseline_commit_id,
    )

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
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
        title="pr requiring one approval",
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

    # --- break exactly one thing: attempt to merge before the rule is satisfied ---
    code, message = _error(
        lambda: cc.merge_pull_request_by_squash(pullRequestId=pr_id, repositoryName=repo_name)
    )
    assert code == "PullRequestApprovalRulesNotSatisfiedException", (
        f"merging an unapproved pull request raised {code!r}, expected "
        "PullRequestApprovalRulesNotSatisfiedException"
    )
    expected = (
        "You cannot merge the pull request because the requirements for one or more approval "
        "rules have not been met. For details about the approval rules that still have "
        "requirements, use EvaluatePullRequestApprovalRules."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: destination branch did not advance, PR is still OPEN
    unmerged_branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert unmerged_branch["commitId"] == baseline_commit_id, (
        f"the refused merge advanced main to {unmerged_branch['commitId']!r}, expected it to "
        f"stay at {baseline_commit_id!r}"
    )
    unmerged_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert unmerged_pr["pullRequestStatus"] == "OPEN", (
        f"the refused merge left the pull request as {unmerged_pr['pullRequestStatus']!r}, "
        "expected OPEN"
    )

    # --- positive control: same merge call succeeds once approved ---
    # The assumed-role session is freshly minted; CodeCommit's own auth path can lag STS by a
    # few seconds, so the first call on it retries through UnrecognizedClientException rather
    # than treating that as a genuine denial.
    _retry_until_propagated(
        lambda: approver_cc.update_pull_request_approval_state(
            pullRequestId=pr_id, revisionId=revision_id, approvalState="APPROVE"
        )
    )
    merge_result = cc.merge_pull_request_by_squash(pullRequestId=pr_id, repositoryName=repo_name)
    assert merge_result["pullRequest"]["pullRequestStatus"] == "CLOSED", (
        "the approved merge left the pull request as "
        f"{merge_result['pullRequest']['pullRequestStatus']!r}, expected CLOSED"
    )
    merged_branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert merged_branch["commitId"] != baseline_commit_id, (
        "the approved merge did not advance main past the pre-approval baseline "
        f"{baseline_commit_id!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_until_propagated(
    fn, *, timeout_s: float = 60.0, interval_s: float = 3.0
) -> Any:
    """Freshly minted STS session credentials can take a few seconds to be honoured by another
    service's auth path; retry on that specific propagation-lag error, never on a genuine
    denial."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("UnrecognizedClientException", "InvalidClientTokenId"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"assumed-role credentials never propagated within {timeout_s}s: {last_exc}"
    )


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
