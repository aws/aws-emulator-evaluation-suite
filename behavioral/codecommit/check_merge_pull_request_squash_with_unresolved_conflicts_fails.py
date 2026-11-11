"""merge-pull-request-squash-with-unresolved-conflicts-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-pull-request-squash-with-unresolved-conflicts-fails"
GROUP = "concurrency"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergePullRequestBySquash with a same-line conflict raises ManualMergeRequiredException and moves
    neither branch nor closes the pull request, while a non-conflicting pull request merges."""
    cc = ctx.client("codecommit")
    repo = _create_repo(ctx)

    base_commit = _put_file(ctx, repo, "main", "shared.txt", b"root\n", parent_commit_id=None)
    cc.create_branch(repositoryName=repo, branchName="feature", commitId=base_commit)

    main_commit = _put_file(
        ctx, repo, "main", "shared.txt", b"main-edit\n", parent_commit_id=base_commit
    )
    feature_commit = _put_file(
        ctx, repo, "feature", "shared.txt", b"feature-edit\n", parent_commit_id=base_commit
    )

    pr = cc.create_pull_request(
        title="conflicting squash merge",
        targets=[
            {
                "repositoryName": repo,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )
    pr_id = pr["pullRequest"]["pullRequestId"]

    code, message = _error(
        lambda: cc.merge_pull_request_by_squash(pullRequestId=pr_id, repositoryName=repo)
    )
    assert code == "ManualMergeRequiredException", f"unexpected error code: {code}"
    assert message == (
        "Current branches cannot be merged, please try to merge using a Git client locally."
    ), message

    # effect absent: destination branch untouched, PR still open
    tip_after = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert tip_after == main_commit, "destination branch must not move on a failed squash merge"

    pr_after = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert pr_after["pullRequestStatus"] == "OPEN", "pull request must remain OPEN after failure"

    feature_tip_after = cc.get_branch(repositoryName=repo, branchName="feature")["branch"]["commitId"]
    assert feature_tip_after == feature_commit, "source branch must not move on a failed squash merge"

    # positive control: a non-conflicting PR against the same repo merges cleanly
    cc.create_branch(repositoryName=repo, branchName="feature2", commitId=main_commit)
    _put_file(ctx, repo, "feature2", "other.txt", b"unrelated\n", parent_commit_id=main_commit)

    pr2 = cc.create_pull_request(
        title="clean squash merge",
        targets=[
            {
                "repositoryName": repo,
                "sourceReference": "feature2",
                "destinationReference": "main",
            }
        ],
    )
    pr2_id = pr2["pullRequest"]["pullRequestId"]
    merge2 = cc.merge_pull_request_by_squash(pullRequestId=pr2_id, repositoryName=repo)
    target2 = merge2["pullRequest"]["pullRequestTargets"][0]
    assert merge2["pullRequest"]["pullRequestStatus"] == "CLOSED", (
        f"positive-control merge must close the PR, got {merge2['pullRequest']['pullRequestStatus']!r}"
    )
    assert target2["mergeMetadata"]["isMerged"] is True, (
        f"positive-control merge must report isMerged=True, got {target2['mergeMetadata'].get('isMerged')!r}"
    )

    tip_final = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert tip_final != main_commit, "positive control merge must advance the destination branch"


def _create_repo(ctx) -> str:
    cc = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-ccrepo-")
    cc.create_repository(repositoryName=name, tags={"sim2real": "ccsqconf"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))
    return name


def _put_file(ctx, repo: str, branch: str, path: str, content: bytes, parent_commit_id):
    cc = ctx.client("codecommit")
    kwargs = {
        "repositoryName": repo,
        "branchName": branch,
        "fileContent": content,
        "filePath": path,
    }
    if parent_commit_id is not None:
        kwargs["parentCommitId"] = parent_commit_id
    resp = cc.put_file(**kwargs)
    return resp["commitId"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
