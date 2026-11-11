"""comment-lifecycle-post-get-update-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "comment-lifecycle-post-get-update-delete"
GROUP = "data-plane"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A comment posted via PostCommentForComparedCommit can be read, updated, and
    content-deleted; afterwards GetComment and UpdateComment on it are both refused."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    c1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"v1\n", filePath="a.txt"
    )["commitId"]
    c2 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"v2\n",
        filePath="a.txt",
        parentCommitId=c1,
    )["commitId"]

    post_resp = cc.post_comment_for_compared_commit(
        repositoryName=repo_name,
        beforeCommitId=c1,
        afterCommitId=c2,
        content="initial comment",
    )
    comment_id = post_resp["comment"]["commentId"]

    got = cc.get_comment(commentId=comment_id)["comment"]
    assert got["content"] == "initial comment", f"expected freshly-posted content, got {got['content']!r}"
    assert got["deleted"] is False, f"expected a live comment, got deleted={got['deleted']!r}"

    updated = cc.update_comment(commentId=comment_id, content="updated comment")["comment"]
    assert updated["content"] == "updated comment", (
        f"expected UpdateComment's own response to echo the new content, got {updated['content']!r}"
    )
    got_after_update = cc.get_comment(commentId=comment_id)["comment"]
    assert got_after_update["content"] == "updated comment", (
        f"expected the independent GetComment read to reflect the update, got {got_after_update['content']!r}"
    )

    deleted = cc.delete_comment_content(commentId=comment_id)["comment"]
    assert deleted["commentId"] == comment_id, f"expected {comment_id!r}, got {deleted['commentId']!r}"
    assert deleted["deleted"] is True, f"expected deleted=True, got {deleted['deleted']!r}"
    assert deleted.get("content", "") == "", f"expected content cleared, got {deleted.get('content')!r}"

    code, message = _error(lambda: cc.get_comment(commentId=comment_id))
    assert code == "CommentDeletedException", f"expected CommentDeletedException, got {code!r}"
    expected_message = (
        "The specified comment has already been marked as deleted.  Verify that "
        "you specified a valid comment ID, and then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # The dead comment is not just unreadable -- it is unusable. A mutation on the
    # same id is refused with the identical specific error, not a generic not-found.
    update_code, update_message = _error(lambda: cc.update_comment(commentId=comment_id, content="after delete"))
    assert update_code == "CommentDeletedException", (
        f"expected UpdateComment on a content-deleted comment to raise CommentDeletedException, got {update_code!r}"
    )
    expected_message = (
        "You cannot delete this comment.  The specified comment has already been "
        "marked as deleted.  Verify that you specified a valid comment ID, and "
        "then try again."
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
