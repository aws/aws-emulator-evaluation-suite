"""get-blob-content-matches-written-file."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-blob-content-matches-written-file"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetBlob returns the exact binary content of a blob created via PutFile, by blob id."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "get-blob-content"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    # Content deliberately includes non-UTF8 bytes to prove byte-exact fidelity, not just text.
    content = bytes(range(256)) + b"\x00binary-blob-payload\xff\xfe\x00\x01"

    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=content,
        filePath="data/payload.bin",
        commitMessage="add binary payload",
    )
    blob_id = put_resp["blobId"]

    blob_resp = cc.get_blob(repositoryName=repo_name, blobId=blob_id)
    retrieved = blob_resp["content"]
    if hasattr(retrieved, "read"):
        retrieved = retrieved.read()

    assert retrieved == content, (
        f"GetBlob content mismatch: expected {len(content)} bytes, got {len(retrieved)} bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
