"""get-blob-differences-between-commits."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-blob-differences-between-commits"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetBlobDifferences reports the diff hunks/sizes for a file modified between two commits."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    content_v1 = b"line one\nline two\nline three\n"
    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=content_v1,
        filePath="notes.txt",
        commitMessage="v1",
    )
    commit1 = put_resp["commitId"]
    blob1 = put_resp["blobId"]

    content_v2 = b"line one\nCHANGED SECOND LINE\nline three\nline four\n"
    commit_resp = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=commit1,
        putFiles=[{"filePath": "notes.txt", "fileContent": content_v2}],
        commitMessage="v2",
    )
    updated = commit_resp["filesUpdated"]
    assert len(updated) == 1, f"expected exactly one updated file, got {updated!r}"
    blob2 = updated[0]["blobId"]
    assert blob2 != blob1, f"expected a new blob id for the changed content, got {blob2!r} == {blob1!r}"

    diff = cc.get_blob_differences(
        repositoryName=repo_name, beforeBlobId=blob1, afterBlobId=blob2
    )

    assert diff["isBinary"] is False, f"expected a text diff, got isBinary={diff['isBinary']!r}"
    assert diff["beforeBlobSize"] == len(content_v1), (
        f"expected beforeBlobSize={len(content_v1)}, got {diff['beforeBlobSize']!r}"
    )
    assert diff["afterBlobSize"] == len(content_v2), (
        f"expected afterBlobSize={len(content_v2)}, got {diff['afterBlobSize']!r}"
    )
    assert len(diff["hunks"]) == 1, f"expected one hunk spanning the whole file, got {diff['hunks']!r}"

    hunk = diff["hunks"][0]
    assert hunk["beforeLineCount"] == 3, hunk
    assert hunk["afterLineCount"] == 4, hunk
    changes = hunk.get("changes", [])
    by_type: dict[str, list[dict]] = {}
    for change in changes:
        by_type.setdefault(change["type"], []).append(change)

    deleted = [c["content"] for c in by_type.get("DELETE", [])]
    added = [c["content"] for c in by_type.get("ADD", [])]
    assert deleted == ["line two"], f"expected the replaced line reported as deleted, got {deleted!r}"
    assert added == ["CHANGED SECOND LINE", "line four"], (
        f"expected the replacement line and the appended line reported as added, got {added!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
