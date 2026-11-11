"""pull-request-reopen-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pull-request-reopen-rejected"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reopening a CLOSED pull request raises InvalidPullRequestStatusUpdateException and it stays
    CLOSED, while a sibling's OPEN -> CLOSED transition succeeds."""
    codecommit = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"# hello\n",
        filePath="README.md",
    )
    main_commit = codecommit.get_branch(repositoryName=repo_name, branchName="main")["branch"]["commitId"]

    # Two independent feature branches so two open pull requests can coexist.
    codecommit.create_branch(repositoryName=repo_name, branchName="feature-a", commitId=main_commit)
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="feature-a",
        fileContent=b"a",
        filePath="a.txt",
        parentCommitId=main_commit,
    )
    codecommit.create_branch(repositoryName=repo_name, branchName="feature-b", commitId=main_commit)
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="feature-b",
        fileContent=b"b",
        filePath="b.txt",
        parentCommitId=main_commit,
    )

    pr1 = codecommit.create_pull_request(
        title=ctx.unique_name("sim2real-behav-pr1-"),
        targets=[{"repositoryName": repo_name, "sourceReference": "feature-a", "destinationReference": "main"}],
    )["pullRequest"]
    pr2 = codecommit.create_pull_request(
        title=ctx.unique_name("sim2real-behav-pr2-"),
        targets=[{"repositoryName": repo_name, "sourceReference": "feature-b", "destinationReference": "main"}],
    )["pullRequest"]
    pr1_id = pr1["pullRequestId"]
    pr2_id = pr2["pullRequestId"]

    # Close pr1 via the one valid transition.
    codecommit.update_pull_request_status(pullRequestId=pr1_id, pullRequestStatus="CLOSED")
    status_after_close = codecommit.get_pull_request(pullRequestId=pr1_id)["pullRequest"]["pullRequestStatus"]
    assert status_after_close == "CLOSED", f"expected pr1 CLOSED after valid transition, got {status_after_close!r}"

    # Break exactly one thing: try to reopen the now-CLOSED pull request.
    code, message = _error(
        lambda: codecommit.update_pull_request_status(pullRequestId=pr1_id, pullRequestStatus="OPEN")
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

    # Effect absent: pr1 is still CLOSED, not reopened.
    status_after_reject = codecommit.get_pull_request(pullRequestId=pr1_id)["pullRequest"]["pullRequestStatus"]
    assert status_after_reject == "CLOSED", f"expected pr1 still CLOSED after rejected reopen, got {status_after_reject!r}"

    # Positive control: the valid OPEN -> CLOSED transition still works on pr2.
    codecommit.update_pull_request_status(pullRequestId=pr2_id, pullRequestStatus="CLOSED")
    pr2_status = codecommit.get_pull_request(pullRequestId=pr2_id)["pullRequest"]["pullRequestStatus"]
    assert pr2_status == "CLOSED", f"expected pr2 CLOSED via the still-valid transition, got {pr2_status!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected reopening a CLOSED pull request to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
