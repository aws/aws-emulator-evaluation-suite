"""approval-rule-name-conflict-rejected."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "approval-rule-name-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["codecommit"]

_RULE_CONTENT = (
    '{"Version": "2018-11-08","Statements": '
    '[{"Type": "Approvers","NumberOfApprovalsNeeded": 1}]}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreatePullRequestApprovalRule calls with the same name yield one winner and one
    ApprovalRuleNameAlreadyExistsException, and the pull request holds exactly one rule of that name."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-arnc-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"init", filePath="README.md"
    )
    base_commit = put1["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    targets = [
        {"repositoryName": repo_name, "sourceReference": "feature", "destinationReference": "main"}
    ]
    created = cc.create_pull_request(title="rule-race-pr", targets=targets)
    pr_id = created["pullRequest"]["pullRequestId"]
    ctx.on_cleanup(
        lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
    )

    rule_name = ctx.unique_name("dup-rule-")
    barrier = threading.Barrier(2)

    def _attempt_create():
        barrier.wait(timeout=10)
        try:
            resp = cc.create_pull_request_approval_rule(
                pullRequestId=pr_id, approvalRuleName=rule_name, approvalRuleContent=_RULE_CONTENT
            )
            return ("ok", resp)
        except Exception as exc:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", (exc.response["Error"]["Code"], exc.response["Error"]["Message"]))
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _attempt_create(), range(2)))

    outcomes = [kind for kind, _ in results]
    assert outcomes.count("ok") == 1, f"expected exactly one winner, got {outcomes}"
    assert outcomes.count("error") == 1, f"expected exactly one loser, got {outcomes}"

    error_payload = next(payload for kind, payload in results if kind == "error")
    assert error_payload == (
        "ApprovalRuleNameAlreadyExistsException",
        "An approval rule already exists with that name. Approval rule names must be unique within "
        "the scope of a pull request.",
    ), f"expected ApprovalRuleNameAlreadyExistsException for the losing create, got {error_payload!r}"

    rules = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    matching = [r for r in rules if r["approvalRuleName"] == rule_name]
    assert len(matching) == 1, f"expected exactly one rule named {rule_name!r}, found {matching}"

    # Positive control: a rule with a genuinely different name is created without conflict.
    other_name = ctx.unique_name("other-rule-")
    other = cc.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName=other_name, approvalRuleContent=_RULE_CONTENT
    )
    assert other["approvalRule"]["approvalRuleName"] == other_name, (
        f"expected the differently-named rule {other_name!r} to be created without conflict, "
        f"got {other['approvalRule']['approvalRuleName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
