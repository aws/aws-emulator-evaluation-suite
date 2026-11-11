"""list-file-commit-history-chronological-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-file-commit-history-chronological-order"
GROUP = "ordering"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFileCommitHistory for a file returns its revisions in strict
    reverse-chronological (newest-first) commit order matching the actual
    write sequence."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-history-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-history"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="f.txt",
        fileContent=b"v1",
    )["commitId"]

    commit2 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="f.txt",
        fileContent=b"v2",
        parentCommitId=commit1,
    )["commitId"]

    commit3 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="f.txt",
        fileContent=b"v3",
        parentCommitId=commit2,
    )["commitId"]

    history = cc.list_file_commit_history(repositoryName=repo_name, filePath="f.txt")
    revision_dag = history["revisionDag"]

    commit_ids_in_order = [entry["commit"]["commitId"] for entry in revision_dag]
    assert commit_ids_in_order == [commit3, commit2, commit1], (
        f"expected newest-first order [{commit3}, {commit2}, {commit1}], "
        f"got {commit_ids_in_order}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
