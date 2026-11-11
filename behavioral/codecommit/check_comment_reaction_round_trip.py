"""comment-reaction-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "comment-reaction-round-trip"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A reaction added via PutCommentReaction is immediately visible via
    GetCommentReactions with correct counts and reactor attribution."""
    cc = ctx.client("codecommit")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]

    repo_name = ctx.unique_name("sim2real-cc-reaction-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-comment-reaction"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="README.md",
        fileContent=b"initial content\n",
    )
    commit1 = put1["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=commit1)
    put2 = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="README.md",
        fileContent=b"changed content\n",
        parentCommitId=commit1,
    )
    commit2 = put2["commitId"]

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

    posted = cc.post_comment_for_pull_request(
        pullRequestId=pr_id,
        repositoryName=repo_name,
        beforeCommitId=commit1,
        afterCommitId=commit2,
        content="looks reasonable",
    )
    comment_id = posted["comment"]["commentId"]

    cc.put_comment_reaction(commentId=comment_id, reactionValue=":thumbsup:")

    reactions = cc.get_comment_reactions(commentId=comment_id)["reactionsForComment"]
    assert len(reactions) == 1, f"expected exactly 1 reaction group, got {reactions}"
    entry = reactions[0]
    assert entry["reaction"]["shortCode"] == ":thumbsup:", entry["reaction"]
    assert entry["reactionUsers"] == [caller_arn], entry["reactionUsers"]
    # Real AWS omits reactionsFromDeletedUsersCount entirely when it is zero.
    assert entry.get("reactionsFromDeletedUsersCount", 0) == 0, entry


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
