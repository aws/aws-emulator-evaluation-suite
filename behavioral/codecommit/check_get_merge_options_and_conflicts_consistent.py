"""get-merge-options-and-conflicts-consistent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-merge-options-and-conflicts-consistent"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMergeOptions lists valid merge strategies for two cleanly-divergent branches, and
    GetMergeConflicts reports mergeable:true with no conflicts for the same pair."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-mergeopt"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"base\n",
        filePath="a.txt",
    )
    base_commit = put_resp["commitId"]

    cc.create_branch(
        repositoryName=repo_name, branchName="feature", commitId=base_commit
    )

    # Non-conflicting change: main touches b.txt, feature touches c.txt.
    cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"only on main\n",
        filePath="b.txt",
        parentCommitId=base_commit,
    )
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"only on feature\n",
        filePath="c.txt",
        parentCommitId=base_commit,
    )

    options = cc.get_merge_options(
        repositoryName=repo_name,
        sourceCommitSpecifier="feature",
        destinationCommitSpecifier="main",
    )
    merge_options = set(options["mergeOptions"])
    assert merge_options >= {"SQUASH_MERGE", "THREE_WAY_MERGE"}, (
        f"expected SQUASH_MERGE and THREE_WAY_MERGE among mergeOptions, got {merge_options}"
    )
    # main and feature each advanced independently past their shared base, so neither is
    # a strict descendant of the other -- fast-forward must not be an available strategy.
    assert "FAST_FORWARD_MERGE" not in merge_options, (
        f"diverged branches must not offer FAST_FORWARD_MERGE, got {merge_options}"
    )

    conflicts = cc.get_merge_conflicts(
        repositoryName=repo_name,
        destinationCommitSpecifier="main",
        sourceCommitSpecifier="feature",
        mergeOption="THREE_WAY_MERGE",
    )
    assert conflicts["mergeable"] is True, f"expected mergeable=True, got {conflicts['mergeable']}"
    assert conflicts["conflictMetadataList"] == [], (
        f"expected no conflicts, got {conflicts['conflictMetadataList']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
