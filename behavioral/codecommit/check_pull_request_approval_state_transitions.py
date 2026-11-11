"""pull-request-approval-state-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pull-request-approval-state-transitions"
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


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating an approval rule, submitting an APPROVE state from a non-author
    identity, and re-evaluating rules moves the pull request's approval status from
    unsatisfied to satisfied, consistently across approval-state reads."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-approvalstate-repo-")

    cc.create_repository(repositoryName=repo_name)
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

    rule = cc.create_pull_request_approval_rule(
        pullRequestId=pr_id,
        approvalRuleName=ctx.unique_name("sim2real-rule-"),
        approvalRuleContent=_RULE_CONTENT,
    )["approvalRule"]
    rule_name = rule["approvalRuleName"]

    # 1. Unsatisfied before any approval.
    states_before = cc.get_pull_request_approval_states(
        pullRequestId=pr_id, revisionId=revision_id
    )["approvals"]
    assert states_before == []

    eval_before = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert eval_before["approved"] is False
    assert rule_name in eval_before["approvalRulesNotSatisfied"]

    # 2. A distinct (non-author) identity approves. IAM policy attachment is
    # eventually consistent, so retry past a transient AccessDenied.
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
            # Fresh assumed-role credentials and a newly-attached IAM policy are
            # both eventually consistent: expect transient AccessDenied (policy
            # not yet effective) or UnrecognizedClientException/InvalidClientTokenId
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

    # 3. Satisfied after approval, consistently visible from both read APIs.
    states_after = cc.get_pull_request_approval_states(
        pullRequestId=pr_id, revisionId=revision_id
    )["approvals"]
    assert len(states_after) == 1
    assert states_after[0]["approvalState"] == "APPROVE"

    eval_after = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert eval_after["approved"] is True
    assert rule_name in eval_after["approvalRulesSatisfied"]
    assert rule_name not in eval_after["approvalRulesNotSatisfied"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
