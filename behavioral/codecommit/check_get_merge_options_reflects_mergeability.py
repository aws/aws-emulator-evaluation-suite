"""get-merge-options-reflects-mergeability."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-merge-options-reflects-mergeability"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMergeOptions reports fast-forward as available for a strictly-ahead
    branch and unavailable once the branches diverge with conflicting edits."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-mergeopt-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="a.txt",
        fileContent=b"base-content",
    )["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base)

    feature_tip = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="a.txt",
        fileContent=b"feature-content",
        parentCommitId=base,
    )["commitId"]

    # feature is a strict descendant of main's current tip (base) -- fast-forward
    # must be an available option.
    before = cc.get_merge_options(
        repositoryName=repo_name,
        sourceCommitSpecifier=feature_tip,
        destinationCommitSpecifier=base,
    )
    options_before_divergence = before["mergeOptions"]
    assert "FAST_FORWARD_MERGE" in options_before_divergence, (
        f"expected FAST_FORWARD_MERGE while feature is a strict descendant of main, "
        f"got {options_before_divergence!r}"
    )
    assert before["baseCommitId"] == base, (
        f"baseCommitId {before['baseCommitId']!r} != the actual branch point {base!r}"
    )
    assert before["sourceCommitId"] == feature_tip, (
        f"sourceCommitId {before['sourceCommitId']!r} != {feature_tip!r}"
    )
    assert before["destinationCommitId"] == base, (
        f"destinationCommitId {before['destinationCommitId']!r} != {base!r}"
    )

    # Now advance main independently with a conflicting edit to the same file,
    # diverging the two branches.
    main_tip = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="a.txt",
        fileContent=b"main-content",
        parentCommitId=base,
    )["commitId"]

    after = cc.get_merge_options(
        repositoryName=repo_name,
        sourceCommitSpecifier=feature_tip,
        destinationCommitSpecifier=main_tip,
    )
    options_after_divergence = after["mergeOptions"]
    assert "FAST_FORWARD_MERGE" not in options_after_divergence, (
        f"expected FAST_FORWARD_MERGE to disappear once main and feature diverge, "
        f"still got {options_after_divergence!r}"
    )
    # Both branches edited the same path with different content, so every strategy
    # -- not just fast-forward -- would produce a real conflict. GetMergeOptions
    # excludes a strategy the moment it would conflict, not only when it would
    # discard commits, so no options remain at all.
    assert options_after_divergence == [], (
        f"a same-path conflicting edit should leave no viable merge strategy, "
        f"got {options_after_divergence!r}"
    )
    assert after["baseCommitId"] == base, (
        f"merge base is {after['baseCommitId']!r}, expected the branch point {base!r}"
    )
    assert after["destinationCommitId"] == main_tip, (
        f"destinationCommitId {after['destinationCommitId']!r} != {main_tip!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
