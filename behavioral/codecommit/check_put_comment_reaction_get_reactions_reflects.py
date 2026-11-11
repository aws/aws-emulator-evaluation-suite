"""put-comment-reaction-get-reactions-reflects."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-comment-reaction-get-reactions-reflects"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A reaction added with PutCommentReaction on a pull-request comment is reflected in the
    counts/users returned by GetCommentReactions."""
    cc = ctx.client("codecommit")
    sts = ctx.client("sts")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base_commit = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"v1\n", filePath="a.txt"
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)
    feature_commit = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"v2\n",
        filePath="a.txt",
        parentCommitId=base_commit,
    )["commitId"]

    pr = cc.create_pull_request(
        title=ctx.unique_name("sim2real-behav-cc-pr-"),
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pull_request_id = pr["pullRequestId"]
    ctx.on_cleanup(
        lambda: cc.update_pull_request_status(
            pullRequestId=pull_request_id, pullRequestStatus="CLOSED"
        )
    )

    comment_resp = cc.post_comment_for_pull_request(
        pullRequestId=pull_request_id,
        repositoryName=repo_name,
        beforeCommitId=base_commit,
        afterCommitId=feature_commit,
        content="LGTM",
    )
    comment_id = comment_resp["comment"]["commentId"]

    caller_arn = sts.get_caller_identity()["Arn"]

    cc.put_comment_reaction(commentId=comment_id, reactionValue=":thumbsup:")

    reactions = cc.get_comment_reactions(commentId=comment_id)["reactionsForComment"]
    assert len(reactions) == 1, f"expected exactly one reaction group, got {reactions}"
    entry = reactions[0]
    short_code = entry["reaction"]["shortCode"]
    assert short_code == ":thumbsup:", f"unexpected shortCode: {entry['reaction']}"
    assert entry["reactionUsers"] == [caller_arn], (
        f"expected reactionUsers == [{caller_arn}], got {entry['reactionUsers']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
