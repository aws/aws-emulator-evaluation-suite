"""get-blob-differences-reflects-change."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-blob-differences-reflects-change"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetBlobDifferences between the before/after blob of a modified file returns hunks
    describing the actual line change, and reports the correct before/after blob sizes."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccgbd"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    content_before = b"alpha\nbravo\ncharlie\n"
    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=content_before,
        filePath="file.txt",
    )
    c1 = put_resp["commitId"]

    content_after = b"alpha\nBRAVO-CHANGED\ncharlie\n"
    cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=content_after,
        filePath="file.txt",
        parentCommitId=c1,
    )

    diffs = cc.get_differences(
        repositoryName=repo_name, beforeCommitSpecifier=c1, afterCommitSpecifier="main"
    )["differences"]
    assert len(diffs) == 1, f"expected exactly one changed file, got {len(diffs)}"
    before_blob_id = diffs[0]["beforeBlob"]["blobId"]
    after_blob_id = diffs[0]["afterBlob"]["blobId"]

    blob_diff = cc.get_blob_differences(
        repositoryName=repo_name, beforeBlobId=before_blob_id, afterBlobId=after_blob_id
    )

    assert blob_diff["isBinary"] is False, "text file must not be reported binary"
    assert blob_diff["beforeBlobSize"] == len(content_before), (
        f"beforeBlobSize {blob_diff['beforeBlobSize']} != actual {len(content_before)}"
    )
    assert blob_diff["afterBlobSize"] == len(content_after), (
        f"afterBlobSize {blob_diff['afterBlobSize']} != actual {len(content_after)}"
    )
    assert len(blob_diff["hunks"]) >= 1, "expected at least one diff hunk for the changed line"

    changes = [c for hunk in blob_diff["hunks"] for c in hunk["changes"]]
    by_type: dict[str, list[str]] = {}
    for c in changes:
        by_type.setdefault(c["type"], []).append(c["content"])

    assert by_type.get("DELETE") == ["bravo"], (
        f"expected exactly the removed line marked DELETE, got {by_type.get('DELETE')}"
    )
    assert by_type.get("ADD") == ["BRAVO-CHANGED"], (
        f"expected exactly the added line marked ADD, got {by_type.get('ADD')}"
    )
    context_lines = by_type.get("CONTEXT", [])
    assert "alpha" in context_lines and "charlie" in context_lines, (
        f"unmodified lines must remain CONTEXT, got CONTEXT={context_lines}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
