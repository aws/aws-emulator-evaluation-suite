"""delete-comment-content-twice-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-comment-content-twice-rejected"
GROUP = "data-plane"
SERVICES = ["codecommit"]


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second DeleteCommentContent on an already-deleted comment is rejected with
    CommentDeletedException, the comment stays in its single deleted state, and the first
    (valid) delete in the same file succeeds normally."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name)
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

    comment_id = cc.post_comment_for_compared_commit(
        repositoryName=repo_name, beforeCommitId=c1, afterCommitId=c2, content="first"
    )["comment"]["commentId"]

    # Positive control: the first delete succeeds and clears content.
    first_delete = cc.delete_comment_content(commentId=comment_id)["comment"]
    assert first_delete["deleted"] is True, f"expected deleted=True after the first delete, got {first_delete.get('deleted')!r}"
    assert first_delete.get("content", "") == "", f"expected content cleared after the first delete, got {first_delete.get('content')!r}"

    # Negative: a second delete on the same, already-deleted comment is rejected.
    code, message = _error(lambda: cc.delete_comment_content(commentId=comment_id))
    assert code == "CommentDeletedException", f"expected CommentDeletedException on re-delete, got {code!r}"
    expected = (
        "You cannot delete this comment.  The specified comment has already been marked as "
        "deleted.  Verify that you specified a valid comment ID, and then try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: state is unchanged -- still simply deleted, not double-processed.
    code_get, message_get = _error(lambda: cc.get_comment(commentId=comment_id))
    assert code_get == "CommentDeletedException", f"expected CommentDeletedException on GetComment after delete, got {code_get!r}"
    expected_get = (
        "The specified comment has already been marked as deleted.  Verify that you specified a "
        "valid comment ID, and then try again."
    )
    assert message_get == expected_get, f"expected message {expected_get!r}, got {message_get!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
