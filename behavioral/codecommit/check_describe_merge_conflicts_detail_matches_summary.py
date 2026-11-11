"""describe-merge-conflicts-detail-matches-summary."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-merge-conflicts-detail-matches-summary"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeMergeConflicts' per-hunk detail is consistent with GetMergeConflicts' summary."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccmc"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"alpha\nbravo\ncharlie\n",
        filePath="conflict.txt",
        commitMessage="base commit",
    )
    base_commit = base["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"alpha\nBRAVO-FROM-MAIN\ncharlie\n",
        filePath="conflict.txt",
        parentCommitId=base_commit,
        commitMessage="change on main",
    )
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"alpha\nbravo-from-feature\ncharlie\n",
        filePath="conflict.txt",
        parentCommitId=base_commit,
        commitMessage="change on feature",
    )

    summary = cc.get_merge_conflicts(
        repositoryName=repo_name,
        destinationCommitSpecifier="main",
        sourceCommitSpecifier="feature",
        mergeOption="THREE_WAY_MERGE",
    )
    assert summary["mergeable"] is False
    summary_meta = summary["conflictMetadataList"][0]
    assert summary_meta["filePath"] == "conflict.txt"

    detail = cc.describe_merge_conflicts(
        repositoryName=repo_name,
        destinationCommitSpecifier="main",
        sourceCommitSpecifier="feature",
        mergeOption="THREE_WAY_MERGE",
        filePath="conflict.txt",
    )

    assert detail["destinationCommitId"] == summary["destinationCommitId"]
    assert detail["sourceCommitId"] == summary["sourceCommitId"]
    assert detail["baseCommitId"] == summary["baseCommitId"]
    assert detail["conflictMetadata"]["filePath"] == "conflict.txt"
    assert detail["conflictMetadata"]["numberOfConflicts"] == summary_meta["numberOfConflicts"]
    assert detail["conflictMetadata"]["contentConflict"] == summary_meta["contentConflict"]
    assert len(detail["mergeHunks"]) >= 1
    assert any(hunk.get("isConflict") for hunk in detail["mergeHunks"]), (
        "expected at least one hunk flagged as a genuine conflict"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
