"""author-cannot-approve-own-pull-request-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "author-cannot-approve-own-pull-request-rejected"
GROUP = "state-machine"
SERVICES = ["codecommit"]

_RULE_CONTENT = (
    '{"Version":"2018-11-08","Statements":'
    '[{"Type":"Approvers","NumberOfApprovalsNeeded":1}]}'
)

_TRUST_POLICY_TMPL = (
    '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",'
    '"Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},'
    '"Action":"sts:AssumeRole"}}]}}'
)


def _error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _make_approver_client(ctx):
    """A CodeCommit client for an IAM role distinct from the caller, so it can approve
    a pull request the caller authored."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cc-approver-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY_TMPL.format(account_id=account_id),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    # IAM role trust/attach is eventually consistent; retry the assume-role past a
    # transient denial while the policy propagates.
    deadline = time.monotonic() + 45
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-approver"
            )["Credentials"]
            # Same endpoint as ctx.client("codecommit"), signed with the assumed role's
            # credentials.
            return ctx.client(
                "codecommit",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "AccessDenied",
                "UnrecognizedClientException",
                "InvalidClientTokenId",
            ):
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not assume approver role after propagation window: {last_exc}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PR author cannot approve their own PR (PullRequestCannotBeApprovedByAuthorException,
    no approval recorded), while a distinct non-author identity approving the same revision
    succeeds, satisfies the rule, and unblocks the merge."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-selfapprove-repo-")

    cc.create_repository(repositoryName=repo_name, tags={"sim2real": CHECK})
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
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"change\n",
        filePath="change.txt",
        parentCommitId=main_head,
        commitMessage="feature change",
        name="sim2real",
        email="sim2real@example.com",
    )

    # The caller creates (and is thus the author of) this pull request.
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

    rule_name = ctx.unique_name("sim2real-selfrule-")
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id,
        approvalRuleName=rule_name,
        approvalRuleContent=_RULE_CONTENT,
    )

    # Break exactly one thing: the author tries to approve their own PR.
    code, message = _error(
        lambda: cc.update_pull_request_approval_state(
            pullRequestId=pr_id, revisionId=revision_id, approvalState="APPROVE"
        )
    )
    assert code == "PullRequestCannotBeApprovedByAuthorException", (
        f"author self-approval raised {code!r}, expected "
        "PullRequestCannotBeApprovedByAuthorException"
    )
    expected_message = (
        "The approval cannot be applied because the user approving the pull "
        "request matches the user who created the pull request. You cannot "
        "approve a pull request that you created."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: no approval was recorded, rule remains unsatisfied.
    approvals = cc.get_pull_request_approval_states(
        pullRequestId=pr_id, revisionId=revision_id
    )["approvals"]
    assert approvals == [], f"a rejected self-approval left approvals={approvals!r}"
    evaluation = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert evaluation["approved"] is False, (
        f"evaluation reports approved={evaluation['approved']!r} with no approval recorded"
    )
    assert rule_name in evaluation["approvalRulesNotSatisfied"], (
        f"approvalRulesNotSatisfied {evaluation['approvalRulesNotSatisfied']!r} is missing "
        f"{rule_name!r}"
    )

    # Positive control: a non-author identity approves the SAME PR and revision, proving the
    # restriction is specific to the author rather than every approval.
    approver_cc = _make_approver_client(ctx)
    deadline = time.monotonic() + 45
    last_exc = None
    while time.monotonic() < deadline:
        try:
            approver_cc.update_pull_request_approval_state(
                pullRequestId=pr_id, revisionId=revision_id, approvalState="APPROVE"
            )
            break
        except ClientError as exc:
            # Fresh assumed-role credentials and a newly-attached IAM policy are both
            # eventually consistent: expect transient AccessDenied (policy not yet
            # effective) or UnrecognizedClientException/InvalidClientTokenId
            # (credentials not yet propagated) for a short window after assume_role.
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

    approvals_after = cc.get_pull_request_approval_states(
        pullRequestId=pr_id, revisionId=revision_id
    )["approvals"]
    assert (
        len(approvals_after) == 1 and approvals_after[0]["approvalState"] == "APPROVE"
    ), f"non-author approval left approvals={approvals_after!r}"

    evaluation_after = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert evaluation_after["approved"] is True, (
        f"evaluation reports approved={evaluation_after['approved']!r} after a valid "
        "non-author approval satisfied the rule"
    )
    assert rule_name in evaluation_after["approvalRulesSatisfied"], (
        f"approvalRulesSatisfied {evaluation_after['approvalRulesSatisfied']!r} is missing "
        f"{rule_name!r}"
    )
    assert rule_name not in evaluation_after["approvalRulesNotSatisfied"], (
        f"approvalRulesNotSatisfied still names the satisfied rule: "
        f"{evaluation_after['approvalRulesNotSatisfied']!r}"
    )

    # Terminal, independent read at the destination: the rule -- satisfied by a real
    # approval, not an override -- is what unblocks the merge.
    cc.merge_pull_request_by_fast_forward(
        pullRequestId=pr_id, repositoryName=repo_name
    )
    merged_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert merged_pr["pullRequestStatus"] == "CLOSED", (
        f"merged pull request status {merged_pr['pullRequestStatus']!r}, expected CLOSED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
