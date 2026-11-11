"""get-merge-conflicts-detects-conflicting-edits."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-merge-conflicts-detects-conflicting-edits"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When two branches modify the same file region, GetMergeConflicts and
    DescribeMergeConflicts both report a real conflict with matching conflict
    metadata; non-conflicting edits on a third branch report none."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-conflict-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccconflict"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="conflict.txt",
        fileContent=b"line1\nline2\nline3\n",
    )["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base)
    cc.create_branch(repositoryName=repo_name, branchName="feature2", commitId=base)

    main_tip = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="conflict.txt",
        fileContent=b"line1\nMAIN-CHANGE\nline3\n",
        parentCommitId=base,
    )["commitId"]

    feature_tip = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="conflict.txt",
        fileContent=b"line1\nFEATURE-CHANGE\nline3\n",
        parentCommitId=base,
    )["commitId"]

    # feature2 touches a different file entirely -- no overlap with main_tip's edit.
    feature2_tip = cc.put_file(
        repositoryName=repo_name,
        branchName="feature2",
        filePath="unrelated.txt",
        fileContent=b"harmless addition",
        parentCommitId=base,
    )["commitId"]

    conflicting = cc.get_merge_conflicts(
        repositoryName=repo_name,
        sourceCommitSpecifier=feature_tip,
        destinationCommitSpecifier=main_tip,
        mergeOption="THREE_WAY_MERGE",
    )
    assert conflicting["mergeable"] is False, (
        f"expected GetMergeConflicts to report unmergeable, got mergeable={conflicting['mergeable']!r}"
    )
    assert len(conflicting["conflictMetadataList"]) == 1, (
        f"expected exactly 1 conflicting file, got {len(conflicting['conflictMetadataList'])}: "
        f"{conflicting['conflictMetadataList']!r}"
    )
    conflict_meta = conflicting["conflictMetadataList"][0]
    assert conflict_meta["filePath"] == "conflict.txt", (
        f"expected the conflicting path to be conflict.txt, got {conflict_meta['filePath']!r}"
    )
    assert conflict_meta["contentConflict"] is True, (
        f"expected contentConflict=True for conflict.txt, got {conflict_meta['contentConflict']!r}"
    )

    described = cc.describe_merge_conflicts(
        repositoryName=repo_name,
        sourceCommitSpecifier=feature_tip,
        destinationCommitSpecifier=main_tip,
        mergeOption="THREE_WAY_MERGE",
        filePath="conflict.txt",
    )
    assert described["conflictMetadata"]["filePath"] == "conflict.txt", (
        f"expected DescribeMergeConflicts to name conflict.txt, "
        f"got {described['conflictMetadata']['filePath']!r}"
    )
    assert described["conflictMetadata"]["contentConflict"] is True, (
        f"expected DescribeMergeConflicts contentConflict=True, "
        f"got {described['conflictMetadata']['contentConflict']!r}"
    )
    assert len(described["mergeHunks"]) >= 1, (
        f"expected at least one merge hunk from DescribeMergeConflicts, "
        f"got {len(described['mergeHunks'])}"
    )

    non_conflicting = cc.get_merge_conflicts(
        repositoryName=repo_name,
        sourceCommitSpecifier=feature2_tip,
        destinationCommitSpecifier=main_tip,
        mergeOption="THREE_WAY_MERGE",
    )
    assert non_conflicting["mergeable"] is True, (
        f"expected the disjoint-file branch to merge cleanly, "
        f"got mergeable={non_conflicting['mergeable']!r}"
    )
    assert non_conflicting["conflictMetadataList"] == [], (
        f"expected no conflicts for the disjoint-file branch, "
        f"got {non_conflicting['conflictMetadataList']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
