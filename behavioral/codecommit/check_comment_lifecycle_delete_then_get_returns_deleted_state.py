"""comment-lifecycle-delete-then-get-returns-deleted-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "comment-lifecycle-delete-then-get-returns-deleted-state"
GROUP = "state-machine"
SERVICES = ["codecommit"]


def _error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteCommentContent, GetComment and a second DeleteCommentContent on the same
    comment both raise CommentDeletedException, not a generic not-found or a success."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-comment-repo-")

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
    feature_head = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"change\n",
        filePath="change.txt",
        parentCommitId=main_head,
        commitMessage="feature change",
        name="sim2real",
        email="sim2real@example.com",
    )["commitId"]

    pr_id = cc.create_pull_request(
        title="Feature PR",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]["pullRequestId"]

    comment = cc.post_comment_for_pull_request(
        pullRequestId=pr_id,
        repositoryName=repo_name,
        beforeCommitId=main_head,
        afterCommitId=feature_head,
        content="original comment content",
    )["comment"]
    comment_id = comment["commentId"]
    assert comment["deleted"] is False, f"expected deleted=False, got {comment.get('deleted')!r}"
    assert comment["content"] == "original comment content", f"expected original content, got {comment.get('content')!r}"

    # Sanity: GetComment before deletion matches what PostComment returned.
    before = cc.get_comment(commentId=comment_id)["comment"]
    assert before["deleted"] is False, f"expected deleted=False, got {before.get('deleted')!r}"
    assert before["content"] == "original comment content", f"expected original content, got {before.get('content')!r}"

    first_delete = cc.delete_comment_content(commentId=comment_id)["comment"]
    assert first_delete["deleted"] is True, f"expected deleted=True, got {first_delete.get('deleted')!r}"
    assert first_delete.get("content", "") == "", f"expected content cleared, got {first_delete.get('content')!r}"

    # GetComment on a content-deleted comment raises CommentDeletedException.
    code, message = _error(lambda: cc.get_comment(commentId=comment_id))
    assert code == "CommentDeletedException", f"expected CommentDeletedException, got {code!r}"
    expected_message = (
        "The specified comment has already been marked as deleted.  Verify that "
        "you specified a valid comment ID, and then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Deleting again is rejected too (content already gone) with the same
    # specific error -- the state is sticky, not reset to a fresh not-found.
    code, message = _error(lambda: cc.delete_comment_content(commentId=comment_id))
    assert code == "CommentDeletedException", f"expected CommentDeletedException, got {code!r}"
    expected_message = (
        "You cannot delete this comment.  The specified comment has already been "
        "marked as deleted.  Verify that you specified a valid comment ID, and "
        "then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    still_code, still_message = _error(lambda: cc.get_comment(commentId=comment_id))
    assert still_code == "CommentDeletedException", f"expected CommentDeletedException, got {still_code!r}"
    expected_message = (
        "The specified comment has already been marked as deleted.  Verify that "
        "you specified a valid comment ID, and then try again."
    )
    assert still_message == expected_message, (
        f"expected message {expected_message!r}, got {still_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
