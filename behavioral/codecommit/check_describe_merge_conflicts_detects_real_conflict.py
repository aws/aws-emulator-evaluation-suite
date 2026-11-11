"""describe-merge-conflicts-detects-real-conflict."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-merge-conflicts-detects-real-conflict"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two branches independently modifying the same line of a file produce a genuine
    line-level conflict reported by DescribeMergeConflicts."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base_content = b"line1\nline2\nline3\n"
    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=base_content,
        filePath="shared.txt",
    )
    base_commit = put_resp["commitId"]

    cc.create_branch(
        repositoryName=repo_name, branchName="feature", commitId=base_commit
    )

    cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"line1\nline2-CHANGED-BY-MAIN\nline3\n",
        filePath="shared.txt",
        parentCommitId=base_commit,
    )
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"line1\nline2-CHANGED-BY-FEATURE\nline3\n",
        filePath="shared.txt",
        parentCommitId=base_commit,
    )

    result = cc.describe_merge_conflicts(
        repositoryName=repo_name,
        destinationCommitSpecifier="main",
        sourceCommitSpecifier="feature",
        mergeOption="THREE_WAY_MERGE",
        filePath="shared.txt",
        conflictDetailLevel="LINE_LEVEL",
    )

    metadata = result["conflictMetadata"]
    assert metadata["contentConflict"] is True, (
        f"expected contentConflict=True for divergent edits to the same line, got {metadata['contentConflict']!r}"
    )
    assert metadata["numberOfConflicts"] >= 1, (
        f"expected >=1 conflict for divergent edits to the same line, got {metadata['numberOfConflicts']!r}"
    )
    assert metadata["filePath"] == "shared.txt", (
        f"expected conflictMetadata.filePath='shared.txt', got {metadata['filePath']!r}"
    )
    assert any(hunk["isConflict"] for hunk in result["mergeHunks"]), (
        f"expected at least one hunk flagged isConflict=True, got {[h['isConflict'] for h in result['mergeHunks']]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
