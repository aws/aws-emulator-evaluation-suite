"""get-differences-between-commits."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-differences-between-commits"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDifferences between two sequential commits reports the added/modified file paths
    matching the actual changes made by CreateCommit."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "get-differences-between-commits"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    content_a1 = b"a version 1\n"
    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=content_a1,
        filePath="a.txt",
    )
    c1 = put_resp["commitId"]

    content_a2 = b"a version 2\n"
    content_b1 = b"b version 1\n"
    commit_resp = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=c1,
        putFiles=[
            {"filePath": "a.txt", "fileContent": content_a2},
            {"filePath": "b.txt", "fileContent": content_b1},
        ],
    )
    c2 = commit_resp["commitId"]

    diffs = cc.get_differences(
        repositoryName=repo_name, beforeCommitSpecifier=c1, afterCommitSpecifier=c2
    )["differences"]

    by_path = {}
    for d in diffs:
        path = (d.get("afterBlob") or d.get("beforeBlob"))["path"]
        by_path[path] = d

    types_by_path = {p: d["changeType"] for p, d in by_path.items()}
    assert types_by_path == {"a.txt": "M", "b.txt": "A"}, (
        f"GetDifferences({c1[:8]}..{c2[:8]}) reported change types {types_by_path}, "
        "expected exactly {'a.txt': 'M', 'b.txt': 'A'}"
    )

    added = by_path["b.txt"]
    assert "beforeBlob" not in added, (
        f"b.txt is newly added but carries a beforeBlob: {added.get('beforeBlob')!r}"
    )
    assert added["afterBlob"]["path"] == "b.txt", (
        f"b.txt afterBlob.path was {added['afterBlob']['path']!r}"
    )

    modified = by_path["a.txt"]
    assert "beforeBlob" in modified and "afterBlob" in modified, (
        f"a.txt was modified but is missing a before/after blob: {modified!r}"
    )
    assert modified["beforeBlob"]["blobId"] != modified["afterBlob"]["blobId"], (
        "a.txt changed content but GetDifferences reported the same blob id before and after"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
