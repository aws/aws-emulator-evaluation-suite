"""pull-request-status-reopen-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pull-request-status-reopen-rejected"
GROUP = "data-plane"
SERVICES = ["codecommit"]


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected an InvalidPullRequestStatusUpdateException, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A pull request's status can move OPEN -> CLOSED, but the reverse
    transition CLOSED -> OPEN is rejected; the status must remain CLOSED and
    the one-directional transition must still have taken effect."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-prstatus-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-pr-status-reopen-rejected"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="a.txt",
        fileContent=b"base",
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="a.txt",
        fileContent=b"feature-change",
        parentCommitId=base,
    )

    pr = cc.create_pull_request(
        title="test pr",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )
    pr_id = pr["pullRequest"]["pullRequestId"]
    status = pr["pullRequest"]["pullRequestStatus"]
    assert status == "OPEN", f"expected a fresh pull request to be OPEN, got {status!r}"

    # Positive control: the allowed direction (OPEN -> CLOSED) succeeds.
    closed = cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
    closed_status = closed["pullRequest"]["pullRequestStatus"]
    assert closed_status == "CLOSED", f"expected OPEN -> CLOSED to succeed, got {closed_status!r}"

    # Negative: the disallowed reverse direction (CLOSED -> OPEN) is rejected.
    code, message = _error(
        lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="OPEN")
    )
    assert code == "InvalidPullRequestStatusUpdateException", (
        f"expected InvalidPullRequestStatusUpdateException for CLOSED -> OPEN, got {code!r}"
    )
    expected_message = (
        "The pull request status update is not valid. The only valid value change is from "
        "Open to Closed."
    )
    assert message == expected_message, (
        f"reopening a CLOSED pull request returned message {message!r}, expected "
        f"{expected_message!r}"
    )

    # Effect absent: the pull request is still CLOSED, not reopened.
    current = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    current_status = current["pullRequestStatus"]
    assert current_status == "CLOSED", (
        f"expected the rejected reopen to leave the pull request CLOSED, got {current_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
