"""get-differences-reflects-file-change."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-differences-reflects-file-change"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDifferences between two commits on the same branch reports exactly
    the files that were added/modified between those PutFile operations."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-diff-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="a.txt",
        fileContent=b"version-1",
    )["commitId"]

    commit2 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="a.txt",
        fileContent=b"version-2",
        parentCommitId=commit1,
    )["commitId"]

    commit3 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="b.txt",
        fileContent=b"brand-new",
        parentCommitId=commit2,
    )["commitId"]

    # Sanity-check the commit chain via GetCommit before trusting the diff.
    got_commit3 = cc.get_commit(repositoryName=repo_name, commitId=commit3)["commit"]
    assert got_commit3["parents"] == [commit2], (
        f"GetCommit({commit3[:8]}) parents {got_commit3['parents']!r} != [{commit2[:8]}]"
    )

    diffs = cc.get_differences(
        repositoryName=repo_name,
        beforeCommitSpecifier=commit1,
        afterCommitSpecifier=commit3,
    )["differences"]

    by_path = {}
    for d in diffs:
        path = (d.get("afterBlob") or d.get("beforeBlob"))["path"]
        by_path[path] = d["changeType"]

    assert by_path == {"a.txt": "M", "b.txt": "A"}, f"unexpected differences: {by_path}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
