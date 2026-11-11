"""get-merge-options-returns-available-strategies."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-merge-options-returns-available-strategies"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMergeOptions returns the merge strategies actually usable for a fast-forwardable pair."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccmergeoptavail"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"base\n",
        filePath="base.txt",
        commitMessage="base commit",
    )
    base_commit = base["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    # main never moves again: feature is a strict, unconflicted descendant of main's tip,
    # so a fast-forward merge of feature into main must be one of the available options.
    feature = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature only\n",
        filePath="feature.txt",
        parentCommitId=base_commit,
        commitMessage="feature-only addition",
    )
    feature_commit = feature["commitId"]

    options = cc.get_merge_options(
        repositoryName=repo_name,
        sourceCommitSpecifier="feature",
        destinationCommitSpecifier="main",
    )

    # main is a strict ancestor of feature, so every merge strategy is legal here, not
    # merely fast-forward: SQUASH_MERGE and THREE_WAY_MERGE always apply when there is no
    # conflict, and FAST_FORWARD_MERGE additionally applies because the history is linear.
    assert set(options["mergeOptions"]) == {
        "FAST_FORWARD_MERGE",
        "SQUASH_MERGE",
        "THREE_WAY_MERGE",
    }, (
        f"main an ancestor of feature, expected all three merge strategies, "
        f"got {options['mergeOptions']!r}"
    )
    assert options["baseCommitId"] == base_commit, (
        f"baseCommitId {options['baseCommitId']!r} != expected {base_commit!r}"
    )
    assert options["sourceCommitId"] == feature_commit, (
        f"sourceCommitId {options['sourceCommitId']!r} != expected {feature_commit!r}"
    )
    assert options["destinationCommitId"] == base_commit, (
        f"destinationCommitId {options['destinationCommitId']!r} != expected {base_commit!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
