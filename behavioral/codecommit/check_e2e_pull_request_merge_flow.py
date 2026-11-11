"""e2e-pull-request-merge-flow."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pull-request-merge-flow"
GROUP = "e2e"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A commented pull request fast-forward merges, closes and moves main to the feature head; after
    DeleteRepository reads and writes raise RepositoryDoesNotExistException."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-e2e-repo-")

    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-e2e-pr-merge"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    # First commit on main (implicitly creates the branch and becomes the default).
    main_put = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"root\n",
        filePath="root.txt",
        commitMessage="initial commit",
        name="sim2real",
        email="sim2real@example.com",
    )
    main_head = main_put["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=main_head)

    feature_put = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature content\n",
        filePath="feature.txt",
        parentCommitId=main_head,
        commitMessage="add feature file",
        name="sim2real",
        email="sim2real@example.com",
    )
    feature_head = feature_put["commitId"]
    assert feature_head != main_head, (
        f"expected feature commit to differ from main commit, both were {main_head!r}"
    )

    pr = cc.create_pull_request(
        title="Add feature file",
        description="Please review",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]
    assert pr["pullRequestStatus"] == "OPEN", (
        f"expected freshly created PR status OPEN, got {pr['pullRequestStatus']!r}"
    )

    comment = cc.post_comment_for_pull_request(
        pullRequestId=pr_id,
        repositoryName=repo_name,
        beforeCommitId=main_head,
        afterCommitId=feature_head,
        content="LGTM",
    )["comment"]
    assert comment["content"] == "LGTM", f"expected comment content 'LGTM', got {comment['content']!r}"

    merge_resp = cc.merge_pull_request_by_fast_forward(
        pullRequestId=pr_id, repositoryName=repo_name
    )["pullRequest"]
    assert merge_resp["pullRequestStatus"] == "CLOSED", (
        f"expected merge response status CLOSED, got {merge_resp['pullRequestStatus']!r}"
    )
    merge_target = merge_resp["pullRequestTargets"][0]
    merge_meta = merge_target["mergeMetadata"]
    assert merge_meta["mergeCommitId"] == feature_head, (
        f"expected mergeCommitId {feature_head!r}, got {merge_meta['mergeCommitId']!r}"
    )
    assert merge_meta["mergeOption"] == "FAST_FORWARD_MERGE", (
        f"expected mergeOption FAST_FORWARD_MERGE, got {merge_meta['mergeOption']!r}"
    )

    fetched_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert fetched_pr["pullRequestStatus"] == "CLOSED", (
        f"expected independent re-read status CLOSED, got {fetched_pr['pullRequestStatus']!r}"
    )
    target = fetched_pr["pullRequestTargets"][0]
    assert target["mergeMetadata"]["isMerged"] is True, (
        f"expected independent re-read mergeMetadata.isMerged True, got {target['mergeMetadata']['isMerged']!r}"
    )

    main_branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert main_branch["commitId"] == feature_head, (
        f"destination branch head did not advance to the merged commit: "
        f"expected {feature_head!r}, got {main_branch['commitId']!r}"
    )

    # The delete is part of the asserted flow, not just cleanup: prove the repo
    # is gone (independent read) and unusable (a mutation on the dead id also
    # fails) -- ctx.on_cleanup's delete_repository is then a harmless no-op.
    cc.delete_repository(repositoryName=repo_name)

    deleted_code, deleted_message = _error(lambda: cc.get_repository(repositoryName=repo_name))
    assert deleted_code == "RepositoryDoesNotExistException", (
        f"expected GetRepository on deleted repo to raise RepositoryDoesNotExistException, "
        f"got {deleted_code!r}"
    )
    missing_expected = f"{repo_name} for {ctx.account}"
    assert deleted_message == missing_expected, (
        f"expected message {missing_expected!r}, got {deleted_message!r}"
    )

    mutate_code, mutate_message = _error(
        lambda: cc.create_branch(
            repositoryName=repo_name, branchName="feature2", commitId=feature_head
        )
    )
    assert mutate_code == "RepositoryDoesNotExistException", (
        f"expected CreateBranch on deleted repo to raise RepositoryDoesNotExistException, "
        f"got {mutate_code!r}"
    )
    assert mutate_message == missing_expected, (
        f"expected message {missing_expected!r}, got {mutate_message!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
