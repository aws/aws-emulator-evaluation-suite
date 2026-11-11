"""put-comment-reaction-invalid-value-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-comment-reaction-invalid-value-rejected"
GROUP = "data-plane"
SERVICES = ["codecommit"]


def _error(fn):
    """Call fn(); return the (code, message) it raised. An unexpected SUCCESS raises, because an
    emulator accepting a value AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutCommentReaction with a reactionValue that is not a supported emoji shortcode is
    rejected with InvalidReactionValueException, no reaction is recorded, and a subsequent
    valid reaction on the same comment still succeeds and is reflected by GetCommentReactions."""
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

    comment_id = cc.post_comment_for_compared_commit(
        repositoryName=repo_name, beforeCommitId=c1, afterCommitId=c2, content="hi"
    )["comment"]["commentId"]

    bad_value = "not-a-real-emoji-shortcode"
    code, message = _error(
        lambda: cc.put_comment_reaction(commentId=comment_id, reactionValue=bad_value)
    )
    assert code == "InvalidReactionValueException", f"expected InvalidReactionValueException, got {code}"
    expected_message = f"Unrecognized Reaction Value: {bad_value}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    reactions = cc.get_comment_reactions(commentId=comment_id)["reactionsForComment"]
    assert reactions == [], f"expected no recorded reaction after rejection, got {reactions}"

    # Positive control: a valid reaction on the same comment succeeds and is reflected.
    cc.put_comment_reaction(commentId=comment_id, reactionValue=":thumbsup:")
    reactions_after = cc.get_comment_reactions(commentId=comment_id)["reactionsForComment"]
    assert len(reactions_after) == 1, f"expected exactly 1 reaction, got {reactions_after}"
    short_code = reactions_after[0]["reaction"]["shortCode"]
    assert short_code == ":thumbsup:", f"expected shortCode ':thumbsup:', got {reactions_after[0]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
