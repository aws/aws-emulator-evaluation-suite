"""client-request-token-required-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "client-request-token-required-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePullRequest with an explicitly empty clientRequestToken raises
    InvalidClientRequestTokenException and creates no pull request."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-crt-required"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="initial commit",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello"}],
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=commit1)

    title = ctx.unique_name("sim2real-pr-title-")
    targets = [{
        "repositoryName": repo_name,
        "sourceReference": "feature",
        "destinationReference": "main",
    }]

    # An explicit empty string is treated as a malformed token, not a missing required field.
    code, message = _error(lambda: cc.create_pull_request(
        title=title, targets=targets, clientRequestToken="",
    ))
    assert code == "InvalidClientRequestTokenException", f"unexpected code: {code}"
    expected_message = (
        "The client request token is not valid. Client request tokens must be "
        "between 1 and 256 alphanumeric characters."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    open_ids = cc.list_pull_requests(
        repositoryName=repo_name, pullRequestStatus="OPEN",
    )["pullRequestIds"]
    assert open_ids == [], f"expected no open pull requests after rejected create, got {open_ids}"

    # positive control: a real token succeeds and the pull request shows up
    pr_id = cc.create_pull_request(
        title=title, targets=targets, clientRequestToken=ctx.unique_name("sim2real-token-"),
    )["pullRequest"]["pullRequestId"]
    ctx.on_cleanup(lambda: cc.update_pull_request_status(
        pullRequestId=pr_id, pullRequestStatus="CLOSED",
    ))
    open_ids2 = cc.list_pull_requests(
        repositoryName=repo_name, pullRequestStatus="OPEN",
    )["pullRequestIds"]
    assert pr_id in open_ids2, f"expected {pr_id} among open pull requests, got {open_ids2}"



def _error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
