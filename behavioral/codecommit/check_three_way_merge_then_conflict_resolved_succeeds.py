"""three-way-merge-then-conflict-resolved-succeeds."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "three-way-merge-then-conflict-resolved-succeeds"
GROUP = "concurrency"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergeBranchesByThreeWay with conflicting edits raises ManualMergeRequiredException and leaves main;
    after a resolving commit the merge creates a two-parent commit and main advances to it."""
    cc = ctx.client("codecommit")
    repo = _create_repo(ctx)

    base_commit = _put_file(ctx, repo, "main", "shared.txt", b"root\n", parent_commit_id=None)
    cc.create_branch(repositoryName=repo, branchName="feature", commitId=base_commit)

    main_commit_1 = _put_file(
        ctx, repo, "main", "shared.txt", b"main-edit\n", parent_commit_id=base_commit
    )
    feature_commit = _put_file(
        ctx, repo, "feature", "shared.txt", b"feature-edit\n", parent_commit_id=base_commit
    )

    # First attempt: real conflicting edits on both sides -> must fail, must not move main.
    code, message = _error(
        lambda: cc.merge_branches_by_three_way(
            repositoryName=repo,
            sourceCommitSpecifier="feature",
            destinationCommitSpecifier="main",
            targetBranch="main",
        )
    )
    assert code == "ManualMergeRequiredException", f"unexpected error code: {code}"
    expected_message = (
        "Current branches cannot be merged, please try to merge using a Git client locally."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tip_after_failed_merge = cc.get_branch(repositoryName=repo, branchName="main")["branch"][
        "commitId"
    ]
    assert tip_after_failed_merge == main_commit_1, "failed merge must not move the target branch"

    # Resolve the conflict: bring main's copy of shared.txt in line with feature's, so the
    # only remaining difference between the branches is history, not content.
    main_commit_2 = _put_file(
        ctx, repo, "main", "shared.txt", b"feature-edit\n", parent_commit_id=main_commit_1
    )

    merge_result = cc.merge_branches_by_three_way(
        repositoryName=repo,
        sourceCommitSpecifier="feature",
        destinationCommitSpecifier="main",
        targetBranch="main",
    )
    merge_commit_id = merge_result["commitId"]
    assert merge_commit_id not in (main_commit_2, feature_commit), (
        "a successful three-way merge must create a brand-new merge commit"
    )

    merge_commit = cc.get_commit(repositoryName=repo, commitId=merge_commit_id)["commit"]
    assert merge_commit["parents"] == [main_commit_2, feature_commit], (
        f"merge commit parents are {merge_commit['parents']!r}; expected exactly "
        f"[{main_commit_2!r}, {feature_commit!r}] -- destination tip then source tip"
    )

    tip_final = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert tip_final == merge_commit_id, "target branch head must advance to the merge commit"


def _create_repo(ctx) -> str:
    cc = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-ccrepo-")
    cc.create_repository(repositoryName=name, tags={"sim2real": "cc3way"})
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
    """Call fn(); return its error code. An unexpected SUCCESS raises, because an emulator ACCEPTING
    a merge real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this conflicting three-way merge, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
