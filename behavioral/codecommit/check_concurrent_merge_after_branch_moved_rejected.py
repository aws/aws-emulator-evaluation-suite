"""concurrent-merge-after-branch-moved-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "concurrent-merge-after-branch-moved-rejected"
GROUP = "concurrency"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A fast-forward merge after main advanced with unrelated history raises
    ManualMergeRequiredException, leaving main and the OPEN pull request unchanged, while a sibling
    pull request merges."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-concur-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccbrmv"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    # Bootstrap main branch with an initial commit.
    c0 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="README.md",
        fileContent=b"init",
    )["commitId"]

    # --- Negative scenario: branch moves after PR creation, before FF merge ---
    cc.create_branch(repositoryName=repo_name, branchName="feature-a", commitId=c0)
    c_feature_a = cc.put_file(
        repositoryName=repo_name,
        branchName="feature-a",
        filePath="feature-a.txt",
        fileContent=b"feature-a-work",
        parentCommitId=c0,
    )["commitId"]

    pr = cc.create_pull_request(
        title="feature-a into main",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature-a",
                "destinationReference": "main",
            }
        ],
    )
    pr_id = pr["pullRequest"]["pullRequestId"]

    # Concurrently advance the destination branch (main) after PR creation.
    c_main_advanced = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="main-advance.txt",
        fileContent=b"main-advanced-concurrently",
        parentCommitId=c0,
    )["commitId"]

    code, message = _error(
        lambda: cc.merge_pull_request_by_fast_forward(
            pullRequestId=pr_id, repositoryName=repo_name
        )
    )
    assert code == "ManualMergeRequiredException", (
        f"expected ManualMergeRequiredException for a fast-forward merge whose destination "
        f"moved concurrently, got {code!r}"
    )
    expected = (
        "Current branches cannot be merged, please try to merge using a Git client locally."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: PR is still OPEN, and main still points at the concurrently
    # advanced commit (not merged, not moved back to the stale base).
    pr_after = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert pr_after["pullRequestStatus"] == "OPEN", (
        f"expected pullRequestStatus OPEN after rejected merge, got {pr_after['pullRequestStatus']!r}"
    )
    branch_after = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch_after["commitId"] == c_main_advanced, (
        f"main should still be at the concurrently-advanced commit {c_main_advanced!r}, "
        f"got {branch_after['commitId']!r}"
    )
    assert c_feature_a != branch_after["commitId"], (
        f"main must not have been fast-forwarded to the feature commit {c_feature_a!r}"
    )

    # --- Positive control: same shape, no concurrent update, merge succeeds ---
    cc.create_branch(
        repositoryName=repo_name, branchName="feature-b", commitId=c_main_advanced
    )
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature-b",
        filePath="feature-b.txt",
        fileContent=b"feature-b-work",
        parentCommitId=c_main_advanced,
    )
    pr2 = cc.create_pull_request(
        title="feature-b into main",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature-b",
                "destinationReference": "main",
            }
        ],
    )
    pr2_id = pr2["pullRequest"]["pullRequestId"]
    merged = cc.merge_pull_request_by_fast_forward(
        pullRequestId=pr2_id, repositoryName=repo_name
    )["pullRequest"]
    target = merged["pullRequestTargets"][0]
    assert target["mergeMetadata"]["isMerged"] is True, (
        f"positive control: expected the unraced merge to report isMerged=True, "
        f"got {target['mergeMetadata']!r}"
    )
    branch_final = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch_final["commitId"] == target["mergeMetadata"]["mergeCommitId"], (
        f"main should be at the merge commit {target['mergeMetadata']['mergeCommitId']!r}, "
        f"got {branch_final['commitId']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
