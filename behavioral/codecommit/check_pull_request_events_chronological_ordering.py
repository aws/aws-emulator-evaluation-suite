"""pull-request-events-chronological-ordering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pull-request-events-chronological-ordering"
GROUP = "ordering"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribePullRequestEvents lists events chronologically: creation, then the source
    reference update from a new commit, then the status change to CLOSED from the merge."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-prevents-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-pr-events-ordering"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    c0 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="README.md",
        fileContent=b"init",
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=c0)
    c_feature = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="feature.txt",
        fileContent=b"feature-work",
        parentCommitId=c0,
    )["commitId"]

    pr = cc.create_pull_request(
        title="feature into main",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )
    pr_id = pr["pullRequest"]["pullRequestId"]

    # Post a comment: exercises the realistic pre-merge PR workflow (comments are
    # NOT represented as PullRequestEvents themselves, so this does not gate the
    # ordering assertion below).
    cc.post_comment_for_pull_request(
        pullRequestId=pr_id,
        repositoryName=repo_name,
        beforeCommitId=c0,
        afterCommitId=c_feature,
        content="looks good to me",
    )

    # Push another commit to the source branch AFTER PR creation: this is a
    # genuine, distinct lifecycle event (source reference updated) that must
    # appear strictly after creation and strictly before the merge/close event.
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="feature2.txt",
        fileContent=b"more-feature-work",
        parentCommitId=c_feature,
    )

    cc.merge_pull_request_by_three_way(pullRequestId=pr_id, repositoryName=repo_name)

    events = cc.describe_pull_request_events(pullRequestId=pr_id)["pullRequestEvents"]
    assert len(events) >= 3, events

    # Chronological invariant: eventDate is non-decreasing across the returned list.
    for i in range(len(events) - 1):
        assert events[i]["eventDate"] <= events[i + 1]["eventDate"], events

    types = [e["pullRequestEventType"] for e in events]
    assert types[0] == "PULL_REQUEST_CREATED", types

    merge_idx = types.index("PULL_REQUEST_MERGE_STATE_CHANGED")
    merge_is_merged = events[merge_idx]["pullRequestMergedStateChangedEventMetadata"][
        "mergeMetadata"
    ]["isMerged"]
    assert merge_is_merged is True, (
        f"expected merge event mergeMetadata.isMerged True, got {merge_is_merged!r}"
    )

    source_update_idx = types.index("PULL_REQUEST_SOURCE_REFERENCE_UPDATED")
    assert 0 < source_update_idx < merge_idx, types

    # The PR itself is CLOSED after the merge, consistent with its event history.
    pr_after = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert pr_after["pullRequestStatus"] == "CLOSED", (
        f"expected independent re-read pullRequestStatus CLOSED, got {pr_after['pullRequestStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

