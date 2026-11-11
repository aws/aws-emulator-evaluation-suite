"""pull-request-comment-thread-anchors-to-the-diff-blob-ids."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pull-request-comment-thread-anchors-to-the-diff-blob-ids"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A pull-request comment and its replies come back as one thread whose before/after blob ids
    are the ones GetDifferences reports for that path, each reply naming the root in inReplyTo; a
    reply to a nonexistent comment is refused with CommentDoesNotExistException.

    Reference: https://docs.aws.amazon.com/codecommit/latest/APIReference/API_GetCommentsForPullRequest.html
    """
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-ccthread-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccthread"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    path = "reviewed.txt"
    before_body = b"line one\nline two\nline three\n"
    after_body = b"line one\nline two CHANGED ON FEATURE\nline three\n"

    main_tip = cc.put_file(
        repositoryName=repo,
        branchName="main",
        filePath=path,
        fileContent=before_body,
        commitMessage="base version",
    )["commitId"]
    cc.create_branch(repositoryName=repo, branchName="feature", commitId=main_tip)
    feature_tip = cc.put_file(
        repositoryName=repo,
        branchName="feature",
        filePath=path,
        fileContent=after_body,
        parentCommitId=main_tip,
        commitMessage="change the reviewed line",
    )["commitId"]
    assert feature_tip != main_tip, "the feature commit did not advance past the base"

    diffs = cc.get_differences(
        repositoryName=repo,
        beforeCommitSpecifier=main_tip,
        afterCommitSpecifier=feature_tip,
    )["differences"]
    changed = [d for d in diffs if d.get("afterBlob", {}).get("path") == path]
    assert len(changed) == 1, (
        f"GetDifferences({main_tip}..{feature_tip}) reports {len(changed)} entries for "
        f"{path!r}, expected exactly 1; the whole anchor derivation depends on there being one"
    )
    expected_before_blob = changed[0]["beforeBlob"]["blobId"]
    expected_after_blob = changed[0]["afterBlob"]["blobId"]
    assert expected_before_blob != expected_after_blob, (
        f"GetDifferences reports the same blobId {expected_before_blob!r} on both sides of a "
        f"modified file; the two versions differ in {len(after_body) - len(before_body)} bytes"
    )

    pr = cc.create_pull_request(
        title="thread anchoring",
        targets=[
            {
                "repositoryName": repo,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]

    location = {"filePath": path, "filePosition": 2, "relativeFileVersion": "AFTER"}
    root = cc.post_comment_for_pull_request(
        pullRequestId=pr_id,
        repositoryName=repo,
        beforeCommitId=main_tip,
        afterCommitId=feature_tip,
        location=location,
        content="root: is this change intentional?",
    )["comment"]
    root_id = root["commentId"]
    assert not root.get("inReplyTo"), (
        f"the root comment reports inReplyTo {root.get('inReplyTo')!r}; a comment posted with "
        f"no parent must report none"
    )

    reply_1 = cc.post_comment_reply(
        inReplyTo=root_id, content="reply one: yes, deliberate."
    )["comment"]
    reply_2 = cc.post_comment_reply(
        inReplyTo=root_id, content="reply two: agreed, shipping it."
    )["comment"]
    for label, reply in (("reply one", reply_1), ("reply two", reply_2)):
        assert reply["inReplyTo"] == root_id, (
            f"{label} reports inReplyTo {reply['inReplyTo']!r}, expected the root comment id "
            f"{root_id!r}"
        )
        assert reply["commentId"] != root_id, (
            f"{label} was given the root comment's id {root_id!r}; a reply is a new comment"
        )
    assert reply_1["commentId"] != reply_2["commentId"], (
        f"both replies share commentId {reply_1['commentId']!r}"
    )

    groups = _all_comment_groups(cc, repo, pr_id, main_tip, feature_tip)
    mine = [g for g in groups if g.get("location", {}).get("filePath") == path]
    assert len(mine) == 1, (
        f"GetCommentsForPullRequest returned {len(mine)} groups for {path!r} out of "
        f"{len(groups)} total, expected exactly 1 -- the root and its two replies share one "
        f"(beforeCommitId, afterCommitId, location) thread, so they must be grouped together"
    )
    group = mine[0]

    assert group["pullRequestId"] == pr_id, (
        f"the group reports pullRequestId {group['pullRequestId']!r}, expected {pr_id!r}"
    )
    assert group["repositoryName"] == repo, (
        f"the group reports repositoryName {group['repositoryName']!r}, expected {repo!r}"
    )
    assert group["beforeCommitId"] == main_tip, (
        f"the group reports beforeCommitId {group['beforeCommitId']!r}, expected the "
        f"destination tip the comment was posted against, {main_tip!r}"
    )
    assert group["afterCommitId"] == feature_tip, (
        f"the group reports afterCommitId {group['afterCommitId']!r}, expected the source tip "
        f"{feature_tip!r}"
    )
    # The anchor law: the thread's blob ids are the diff's blob ids for the same path.
    assert group["beforeBlobId"] == expected_before_blob, (
        f"the comment thread reports beforeBlobId {group['beforeBlobId']!r}, but "
        f"GetDifferences reports beforeBlob.blobId {expected_before_blob!r} for {path!r} "
        f"between {main_tip} and {feature_tip}. A comment must be anchored to the file version "
        f"it is about, or it cannot survive a rebase"
    )
    assert group["afterBlobId"] == expected_after_blob, (
        f"the comment thread reports afterBlobId {group['afterBlobId']!r}, but GetDifferences "
        f"reports afterBlob.blobId {expected_after_blob!r} for {path!r}"
    )
    assert group["location"] == location, (
        f"the group reports location {group['location']!r}, expected the posted location "
        f"{location!r} verbatim"
    )

    comments = {c["commentId"]: c for c in group["comments"]}
    expected_ids = {root_id, reply_1["commentId"], reply_2["commentId"]}
    assert set(comments) == expected_ids, (
        f"the thread contains comment ids {sorted(comments)!r}, expected exactly the three "
        f"posted, {sorted(expected_ids)!r}"
    )
    assert not comments[root_id].get("inReplyTo"), (
        f"read back through GetCommentsForPullRequest, the root comment reports inReplyTo "
        f"{comments[root_id].get('inReplyTo')!r}; expected none"
    )
    for rid in (reply_1["commentId"], reply_2["commentId"]):
        assert comments[rid]["inReplyTo"] == root_id, (
            f"read back through GetCommentsForPullRequest, reply {rid!r} reports inReplyTo "
            f"{comments[rid]['inReplyTo']!r}, expected the root {root_id!r} -- a flattened "
            f"thread cannot be rendered as a conversation"
        )
    assert comments[root_id]["content"] == "root: is this change intentional?", (
        f"the root comment's content read back as {comments[root_id]['content']!r}"
    )
    assert comments[reply_1["commentId"]]["content"] == "reply one: yes, deliberate.", (
        f"reply one's content read back as {comments[reply_1['commentId']]['content']!r}"
    )

    # Dates, not list positions: the response shape promises no ordering.
    dates = [
        comments[root_id]["creationDate"],
        comments[reply_1["commentId"]]["creationDate"],
        comments[reply_2["commentId"]]["creationDate"],
    ]
    assert dates == sorted(dates), (
        f"creationDates in posting order are {dates!r}, which is not non-decreasing; the root "
        f"was posted before reply one, which was posted before reply two"
    )

    # A commentId is two uuids joined by a colon; a single-uuid placeholder is malformed and
    # draws InvalidCommentIdException instead of the not-found error.
    absent_id = (
        "00000000-0000-0000-0000-000000000000:00000000-0000-0000-0000-000000000000"
    )
    assert absent_id not in comments, (
        f"the placeholder id {absent_id!r} collides with a real comment in this thread"
    )
    code, message = _error(
        lambda: cc.post_comment_reply(inReplyTo=absent_id, content="reply to nothing")
    )
    assert code == "CommentDoesNotExistException", (
        f"PostCommentReply(inReplyTo={absent_id!r}) returned {code!r}, expected "
        f"'CommentDoesNotExistException'"
    )
    expected_message = f"The following comment ID does not exist: {absent_id}"
    assert message == expected_message, (
        f"PostCommentReply(inReplyTo={absent_id!r}) returned message {message!r}, expected "
        f"{expected_message!r}"
    )
    # Effect absent: the thread still holds exactly the three real comments.
    after_groups = [
        g
        for g in _all_comment_groups(cc, repo, pr_id, main_tip, feature_tip)
        if g.get("location", {}).get("filePath") == path
    ]
    assert len(after_groups) == 1, (
        f"the refused reply left {len(after_groups)} groups for {path!r}, expected 1"
    )
    assert {c["commentId"] for c in after_groups[0]["comments"]} == expected_ids, (
        f"the refused reply changed the thread to "
        f"{sorted(c['commentId'] for c in after_groups[0]['comments'])!r}, expected the "
        f"unchanged {sorted(expected_ids)!r}"
    )


def _all_comment_groups(
    cc, repo: str, pr_id: str, before_commit_id: str, after_commit_id: str
) -> list[dict]:
    """Every commentsForPullRequestData group, following nextToken to exhaustion.

    With repositoryName, AWS also requires the commit ids (CommitIdRequiredException otherwise).
    """
    groups: list[dict] = []
    token = None
    while True:
        kwargs = {
            "pullRequestId": pr_id,
            "repositoryName": repo,
            "beforeCommitId": before_commit_id,
            "afterCommitId": after_commit_id,
        }
        if token:
            kwargs["nextToken"] = token
        page = cc.get_comments_for_pull_request(**kwargs)
        # Subscripted so a missing key surfaces as a KeyError, not an empty list.
        groups.extend(page["commentsForPullRequestData"])
        token = page.get("nextToken")
        if not token:
            return groups


def _error(fn):
    """The (code, message) ``fn`` raised; raises on unexpected success."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        "PostCommentReply against an id that names no comment SUCCEEDED; it must be refused"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
