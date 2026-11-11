"""pull-request-reopen-after-close-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pull-request-reopen-after-close-rejected"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CLOSED pull request cannot be reopened via UpdatePullRequestStatus (one-directional transition)."""
    cc = ctx.client("codecommit")
    repo_name = _create_repo(ctx)
    pr_id = _create_open_pr(ctx, repo_name)

    closed = cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")[
        "pullRequest"
    ]
    assert closed["pullRequestStatus"] == "CLOSED", (
        f"expected CLOSED after the valid OPEN->CLOSED transition, got {closed['pullRequestStatus']!r}"
    )

    code, message = _error(
        lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="OPEN")
    )
    assert code == "InvalidPullRequestStatusUpdateException", (
        f"expected InvalidPullRequestStatusUpdateException reopening a CLOSED pull request, got {code!r}"
    )
    expected_message = (
        "The pull request status update is not valid. The only valid value change is from "
        "Open to Closed."
    )
    assert message == expected_message, (
        f"reopening a CLOSED pull request returned message {message!r}, expected "
        f"{expected_message!r}"
    )

    # effect absent: still CLOSED, not reopened (independent read, not the mutating call's own response)
    still_closed = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert still_closed["pullRequestStatus"] == "CLOSED", (
        f"expected the rejected reopen to leave the pull request CLOSED, got {still_closed['pullRequestStatus']!r}"
    )

    # positive control: a fresh OPEN pull request can be closed successfully -- proves
    # UpdatePullRequestStatus is not broken account-wide, only the CLOSED->OPEN direction.
    second_pr_id = _create_open_pr(ctx, repo_name)
    cc.update_pull_request_status(pullRequestId=second_pr_id, pullRequestStatus="CLOSED")

    # terminal assertion: independent read at the destination, through a different operation
    # than the one that mutated.
    control = cc.get_pull_request(pullRequestId=second_pr_id)["pullRequest"]
    assert control["pullRequestStatus"] == "CLOSED", (
        f"positive control: expected the sibling pull request's OPEN->CLOSED transition to have "
        f"taken effect, got {control['pullRequestStatus']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_repo(ctx) -> str:
    cc: Any = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-repo-")
    cc.create_repository(repositoryName=name, tags={"sim2real": "pr-reopen-after-close"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))

    initial_commit_id = cc.create_commit(
        repositoryName=name,
        branchName="main",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello world"}],
        commitMessage="initial commit",
    )["commitId"]
    cc.create_branch(repositoryName=name, branchName="feature", commitId=initial_commit_id)
    cc.create_commit(
        repositoryName=name,
        branchName="feature",
        parentCommitId=initial_commit_id,
        putFiles=[{"filePath": "feature.txt", "fileContent": b"feature content"}],
        commitMessage="feature commit",
    )
    return name


def _create_open_pr(ctx, repo_name: str) -> str:
    cc: Any = ctx.client("codecommit")
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
    return pr_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
