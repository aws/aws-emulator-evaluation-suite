"""comment-content-required-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "comment-content-required-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PostCommentForComparedCommit called with empty content raises
    CommentContentRequiredException (not a generic validation error) and leaves no
    comment behind on the comparison."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="initial commit",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello"}],
    )["commitId"]
    commit2 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=commit1,
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="second commit",
        putFiles=[{"filePath": "second.txt", "fileContent": b"world"}],
    )["commitId"]

    code, message = _error(lambda: cc.post_comment_for_compared_commit(
        repositoryName=repo_name, beforeCommitId=commit1, afterCommitId=commit2, content="",
    ))
    assert code == "CommentContentRequiredException", f"unexpected code: {code}"
    expected_message = (
        "The comment could not be saved because no content was provided. "
        "Comments cannot be empty."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    before = cc.get_comments_for_compared_commit(
        repositoryName=repo_name, beforeCommitId=commit1, afterCommitId=commit2,
    )["commentsForComparedCommitData"]
    before_contents = [c["content"] for entry in before for c in entry.get("comments", [])]
    assert before_contents == [], f"expected no comments on the comparison, found {before_contents!r}"

    # positive control: real content succeeds and shows up on the comparison
    cc.post_comment_for_compared_commit(
        repositoryName=repo_name, beforeCommitId=commit1, afterCommitId=commit2,
        content="looks good",
    )
    after = cc.get_comments_for_compared_commit(
        repositoryName=repo_name, beforeCommitId=commit1, afterCommitId=commit2,
    )["commentsForComparedCommitData"]
    after_contents = [c["content"] for entry in after for c in entry.get("comments", [])]
    assert "looks good" in after_contents, (
        f"expected 'looks good' among comment contents, got {after_contents!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
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
