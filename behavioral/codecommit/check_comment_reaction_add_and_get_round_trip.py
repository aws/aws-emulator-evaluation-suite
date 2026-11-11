"""comment-reaction-add-and-get-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "comment-reaction-add-and-get-round-trip"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutCommentReaction on a PR comment is retrievable via GetCommentReactions with the
    same reaction value and attributed to the caller."""
    cc = ctx.client("codecommit")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]

    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-reaction"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"line one\nline two\n",
        filePath="readme.md",
        commitMessage="base",
    )
    base_commit = base["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)
    feature = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"line one\nline two CHANGED\n",
        filePath="readme.md",
        parentCommitId=base_commit,
        commitMessage="feature change",
    )
    feature_commit = feature["commitId"]

    pr = cc.create_pull_request(
        title=ctx.unique_name("sim2real-pr-"),
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]
    ctx.on_cleanup(lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED"))

    comment_resp = cc.post_comment_for_pull_request(
        pullRequestId=pr_id,
        repositoryName=repo_name,
        beforeCommitId=base_commit,
        afterCommitId=feature_commit,
        content="please review this change",
        location={"filePath": "readme.md", "filePosition": 2, "relativeFileVersion": "AFTER"},
    )
    comment_id = comment_resp["comment"]["commentId"]

    cc.put_comment_reaction(commentId=comment_id, reactionValue=":thumbsup:")

    reactions = cc.get_comment_reactions(commentId=comment_id)["reactionsForComment"]
    assert len(reactions) == 1, reactions
    entry = reactions[0]
    # AWS resolves the ":thumbsup:" shortcode to its emoji glyph and echoes both back.
    assert entry["reaction"]["shortCode"] == ":thumbsup:", entry["reaction"]
    assert entry["reaction"]["emoji"] == "\U0001F44D", entry["reaction"]
    assert caller_arn in entry["reactionUsers"], entry["reactionUsers"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
