"""pull-request-lifecycle-create-merge-close."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pull-request-lifecycle-create-merge-close"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created pull request is OPEN, and MergePullRequestByFastForward closes it with merge metadata."""
    cc = ctx.client("codecommit")
    repo_name = _create_repo(ctx)

    initial_commit_id = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello world"}],
        commitMessage="initial commit",
    )["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=initial_commit_id)

    source_commit_id = cc.create_commit(
        repositoryName=repo_name,
        branchName="feature",
        parentCommitId=initial_commit_id,
        putFiles=[{"filePath": "feature.txt", "fileContent": b"feature content"}],
        commitMessage="feature commit",
    )["commitId"]

    pr = cc.create_pull_request(
        title=ctx.unique_name("sim2real-behav-pr-"),
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]

    def _cleanup():
        try:
            cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "EncryptionKeyNotFoundException",
                "PullRequestDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)

    fetched = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert fetched["pullRequestStatus"] == "OPEN", (
        f"expected freshly created PR status OPEN, got {fetched['pullRequestStatus']!r}"
    )
    initial_is_merged = fetched["pullRequestTargets"][0].get("mergeMetadata", {}).get("isMerged", False)
    assert initial_is_merged is False, (
        f"expected mergeMetadata.isMerged False before any merge, got {initial_is_merged!r}"
    )

    merged = cc.merge_pull_request_by_fast_forward(
        pullRequestId=pr_id,
        repositoryName=repo_name,
        sourceCommitId=source_commit_id,
    )["pullRequest"]
    assert merged["pullRequestStatus"] == "CLOSED", (
        f"expected merge response status CLOSED, got {merged['pullRequestStatus']!r}"
    )

    target = merged["pullRequestTargets"][0]
    merge_meta = target["mergeMetadata"]
    assert merge_meta["isMerged"] is True, (
        f"expected mergeMetadata.isMerged True on merge response, got {merge_meta['isMerged']!r}"
    )
    assert merge_meta["mergeCommitId"] == source_commit_id, (
        f"expected mergeCommitId {source_commit_id!r}, got {merge_meta['mergeCommitId']!r}"
    )
    assert merge_meta["mergeOption"] == "FAST_FORWARD_MERGE", (
        f"expected mergeOption FAST_FORWARD_MERGE, got {merge_meta['mergeOption']!r}"
    )

    after = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert after["pullRequestStatus"] == "CLOSED", (
        f"expected independent re-read status CLOSED, got {after['pullRequestStatus']!r}"
    )
    after_is_merged = after["pullRequestTargets"][0]["mergeMetadata"]["isMerged"]
    assert after_is_merged is True, (
        f"expected independent re-read mergeMetadata.isMerged True, got {after_is_merged!r}"
    )

    branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch["commitId"] == source_commit_id, (
        f"expected destination branch head to advance to merged commit {source_commit_id!r}, "
        f"got {branch['commitId']!r}"
    )


def _create_repo(ctx) -> str:
    cc: Any = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-repo-")
    cc.create_repository(repositoryName=name, tags={"sim2real": "cc-pr-lifecycle"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
