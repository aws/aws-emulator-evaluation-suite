"""post-comment-same-before-after-commit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "post-comment-same-before-after-commit-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PostCommentForComparedCommit with identical beforeCommitId and afterCommitId is
    rejected with BeforeCommitIdAndAfterCommitIdAreSameException instead of posting a
    zero-diff comment, and no comment is created as a side effect of the rejected call."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-pcsbac-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"one", filePath="a.txt"
    )
    commit1 = put1["commitId"]
    put2 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"two",
        filePath="b.txt",
        parentCommitId=commit1,
    )
    commit2 = put2["commitId"]

    # Unlike PostCommentForComparedCommit, GetCommentsForComparedCommit accepts an
    # identical before/after pair (confirmed on real AWS), so it is a valid independent
    # read of the exact destination the rejected post targeted.
    same_pair_count_before = len(
        cc.get_comments_for_compared_commit(
            repositoryName=repo_name, beforeCommitId=commit2, afterCommitId=commit2
        )["commentsForComparedCommitData"]
    )
    assert same_pair_count_before == 0, (
        f"expected no pre-existing comments on (commit2, commit2), got {same_pair_count_before}"
    )

    code, message = _error(
        lambda: cc.post_comment_for_compared_commit(
            repositoryName=repo_name,
            beforeCommitId=commit2,
            afterCommitId=commit2,
            content="zero-diff comment attempt",
        )
    )
    assert code == "BeforeCommitIdAndAfterCommitIdAreSameException", (
        f"expected BeforeCommitIdAndAfterCommitIdAreSameException, got {code!r}"
    )
    assert message == (
        "The before commit ID and the after commit ID are the same, which is not valid. "
        "The before commit ID and the after commit ID must be different commit IDs."
    ), message

    same_pair_count_after = len(
        cc.get_comments_for_compared_commit(
            repositoryName=repo_name, beforeCommitId=commit2, afterCommitId=commit2
        )["commentsForComparedCommitData"]
    )
    assert same_pair_count_after == same_pair_count_before == 0, (
        "the rejected post must not have created a readable comment on (commit2, commit2): "
        f"before={same_pair_count_before}, after={same_pair_count_after}"
    )

    unrelated_pair_count = len(
        cc.get_comments_for_compared_commit(
            repositoryName=repo_name, beforeCommitId=commit1, afterCommitId=commit2
        )["commentsForComparedCommitData"]
    )
    assert unrelated_pair_count == 0, (
        "the rejected same-commit post must not have leaked a comment onto the unrelated "
        f"(commit1, commit2) pair, got {unrelated_pair_count} comment(s)"
    )

    # Positive control: distinct before/after commits accept the comment normally.
    posted = cc.post_comment_for_compared_commit(
        repositoryName=repo_name,
        beforeCommitId=commit1,
        afterCommitId=commit2,
        content="real diff comment",
    )
    assert posted["comment"]["content"] == "real diff comment", (
        f"expected posted comment content 'real diff comment', got {posted['comment']['content']!r}"
    )

    final_count = len(
        cc.get_comments_for_compared_commit(
            repositoryName=repo_name, beforeCommitId=commit1, afterCommitId=commit2
        )["commentsForComparedCommitData"]
    )
    assert final_count == 1, f"expected exactly 1 comment on (commit1, commit2), got {final_count}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
