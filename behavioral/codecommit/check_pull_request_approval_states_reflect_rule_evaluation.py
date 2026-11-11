"""pull-request-approval-states-reflect-rule-evaluation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pull-request-approval-states-reflect-rule-evaluation"
GROUP = "data-plane"
SERVICES = ["codecommit"]

_RULE_CONTENT = (
    '{"Version":"2018-11-08","Statements":'
    '[{"Type":"Approvers","NumberOfApprovalsNeeded":1}]}'
)

_AUTHOR_MESSAGE = (
    "The approval cannot be applied because the user approving the pull request matches the "
    "user who created the pull request. You cannot approve a pull request that you created."
)

_TRUST_POLICY_TMPL = (
    '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",'
    '"Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},'
    '"Action":"sts:AssumeRole"}}]}}'
)


def _client_error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _make_approver_identity(ctx):
    """Create an IAM role distinct from the caller, so it can approve a PR the
    caller authored (CodeCommit forbids self-approval by the PR's author ARN)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cc-approver-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY_TMPL.format(account_id=account_id),
    )
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AWSCodeCommitPowerUser",
    )

    def _cleanup_role():
        iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
        )
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # IAM role trust/attach is eventually consistent; retry the assume-role.
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-approver"
            )["Credentials"]
            return ctx.client(
                "codecommit",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not assume approver role after propagation window: {last_exc}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Approval states and rule evaluation both reflect UpdatePullRequestApprovalState: the
    author's APPROVE and REVOKE are rejected without a trace, and a non-author approval
    flips the evaluation."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name)
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

    rule = cc.create_pull_request_approval_rule(
        pullRequestId=pr_id,
        approvalRuleName=ctx.unique_name("sim2real-rule-"),
        approvalRuleContent=_RULE_CONTENT,
    )["approvalRule"]
    rule_name = rule["approvalRuleName"]

    eval_before = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert eval_before["approved"] is False, eval_before
    assert rule_name in eval_before["approvalRulesNotSatisfied"], eval_before

    # Negative: the pull request's author (the caller, here) can never approve their own PR.
    code, message = _client_error(
        lambda: cc.update_pull_request_approval_state(
            pullRequestId=pr_id, revisionId=revision_id, approvalState="APPROVE"
        )
    )
    assert code == "PullRequestCannotBeApprovedByAuthorException", code
    assert message == _AUTHOR_MESSAGE, message

    # Effect absent: no approval was recorded as a side effect of the rejected call, and the
    # rule's evaluation is untouched.
    approvals_after_reject = cc.get_pull_request_approval_states(
        pullRequestId=pr_id, revisionId=revision_id
    )["approvals"]
    assert approvals_after_reject == [], approvals_after_reject
    eval_after_reject = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert eval_after_reject["approved"] is False, eval_after_reject

    # REVOKE by the author is rejected too; like APPROVE above, this alone cannot rule out a
    # blanket rejection of the operation, which the positive control below does.
    code_revoke, message_revoke = _client_error(
        lambda: cc.update_pull_request_approval_state(
            pullRequestId=pr_id, revisionId=revision_id, approvalState="REVOKE"
        )
    )
    assert code_revoke == "PullRequestCannotBeApprovedByAuthorException", code_revoke
    assert message_revoke == _AUTHOR_MESSAGE, message_revoke
    approvals_after_revoke = cc.get_pull_request_approval_states(
        pullRequestId=pr_id, revisionId=revision_id
    )["approvals"]
    assert approvals_after_revoke == [], approvals_after_revoke

    # Positive control: a non-author identity issuing the IDENTICAL call succeeds, and the
    # approval-states read and the rule evaluation flip in step.
    approver_cc = _make_approver_identity(ctx)
    deadline = time.monotonic() + 45
    last_exc = None
    while time.monotonic() < deadline:
        try:
            approver_cc.update_pull_request_approval_state(
                pullRequestId=pr_id, revisionId=revision_id, approvalState="APPROVE"
            )
            break
        except ClientError as exc:
            # Fresh assumed-role credentials and a newly-attached IAM policy are both eventually
            # consistent: expect transient AccessDenied (policy not yet effective) or
            # UnrecognizedClientException/InvalidClientTokenId (credentials not yet propagated)
            # for a short window after assume_role.
            if exc.response["Error"]["Code"] not in (
                "AccessDeniedException",
                "UnrecognizedClientException",
                "InvalidClientTokenId",
            ):
                raise
            last_exc = exc
            time.sleep(2)
    else:
        raise AssertionError(f"approver role never gained effective permissions: {last_exc}")

    approvals_after_approve = cc.get_pull_request_approval_states(
        pullRequestId=pr_id, revisionId=revision_id
    )["approvals"]
    assert len(approvals_after_approve) == 1, approvals_after_approve
    assert approvals_after_approve[0]["approvalState"] == "APPROVE", approvals_after_approve

    eval_after_approve = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert eval_after_approve["approved"] is True, eval_after_approve
    assert rule_name in eval_after_approve["approvalRulesSatisfied"], eval_after_approve



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
