"""file-commit-history-ordering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "file-commit-history-ordering"
GROUP = "ordering"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFileCommitHistory for a repeatedly-modified file returns its versions in
    strict reverse-chronological order (newest commit first), matching the actual
    sequence in which PutFile calls were made."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-filehist-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccfilehist"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    path = "hist.txt"
    c1 = cc.put_file(
        repositoryName=repo_name, branchName="main", filePath=path, fileContent=b"v1"
    )["commitId"]
    c2 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath=path,
        fileContent=b"v2",
        parentCommitId=c1,
    )["commitId"]
    c3 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath=path,
        fileContent=b"v3",
        parentCommitId=c2,
    )["commitId"]

    history = cc.list_file_commit_history(repositoryName=repo_name, filePath=path)
    dag = history["revisionDag"]
    commit_ids = [entry["commit"]["commitId"] for entry in dag]

    assert len(commit_ids) == 3, f"expected 3 revisions, got {len(commit_ids)}: {commit_ids}"
    assert commit_ids == [c3, c2, c1], (
        f"expected newest-first order [{c3}, {c2}, {c1}], got {commit_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
