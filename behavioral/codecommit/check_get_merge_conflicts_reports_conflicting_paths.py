"""get-merge-conflicts-reports-conflicting-paths."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-merge-conflicts-reports-conflicting-paths"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMergeConflicts between two divergent branches lists the conflicting file path."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccgmc"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"base content\n",
        filePath="conflict.txt",
        commitMessage="base commit",
    )
    base_commit = base["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"main-branch change\n",
        filePath="conflict.txt",
        parentCommitId=base_commit,
        commitMessage="change on main",
    )
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature-branch change\n",
        filePath="conflict.txt",
        parentCommitId=base_commit,
        commitMessage="change on feature",
    )

    conflicts = cc.get_merge_conflicts(
        repositoryName=repo_name,
        destinationCommitSpecifier="main",
        sourceCommitSpecifier="feature",
        mergeOption="THREE_WAY_MERGE",
    )

    assert conflicts["mergeable"] is False, (
        f"expected diverging edits to the same file to be unmergeable, got mergeable={conflicts['mergeable']!r}"
    )
    paths = {c["filePath"] for c in conflicts["conflictMetadataList"]}
    assert paths == {"conflict.txt"}, f"expected exactly conflict.txt, got {paths}"
    content_conflict = conflicts["conflictMetadataList"][0]["contentConflict"]
    assert content_conflict is True, (
        f"expected contentConflict=True for divergent edits to the same file, got {content_conflict!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
