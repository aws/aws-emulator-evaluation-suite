"""update-title-on-closed-pull-request-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-title-on-closed-pull-request-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePullRequestTitle on a CLOSED pull request raises
    PullRequestAlreadyClosedException and the title is left unchanged; the same
    operation succeeds while the pull request is still OPEN."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccuptc"})
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
    cc.create_commit(
        repositoryName=repo_name,
        branchName="feature",
        parentCommitId=commit1,
        putFiles=[{"filePath": "feature.txt", "fileContent": b"feature"}],
    )

    original_title = ctx.unique_name("sim2real-pr-title-")
    pr_id = cc.create_pull_request(
        title=original_title,
        targets=[{
            "repositoryName": repo_name,
            "sourceReference": "feature",
            "destinationReference": "main",
        }],
        clientRequestToken=ctx.unique_name("sim2real-token-"),
    )["pullRequest"]["pullRequestId"]

    # positive control while still OPEN: a title update succeeds
    updated_title = original_title + "-updated"
    cc.update_pull_request_title(pullRequestId=pr_id, title=updated_title)
    got = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["title"]
    assert got == updated_title

    cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
    closed_status = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["pullRequestStatus"]
    assert closed_status == "CLOSED", f"unexpected status: {closed_status}"

    code, message = _error(lambda: cc.update_pull_request_title(
        pullRequestId=pr_id, title="post-close-title",
    ))
    assert code == "PullRequestAlreadyClosedException", f"unexpected code: {code}"
    expected_message = (
        "The change cannot be made because the state of the pull request is CLOSED. "
        "You cannot update the title or description of a pull request after it has "
        "been closed."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    final_title = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["title"]
    assert final_title == updated_title


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
