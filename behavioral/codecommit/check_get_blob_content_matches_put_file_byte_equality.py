"""get-blob-content-matches-put-file-byte-equality."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-blob-content-matches-put-file-byte-equality"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The blob retrieved via GetBlob for a file's blobId is byte-identical to
    the content originally supplied to PutFile, including binary content."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-blob-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccblobeq"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    # Binary content spanning the full byte range, including NUL bytes and
    # sequences that are not valid UTF-8 -- a faithful blob store must not
    # mangle or re-encode this.
    binary_content = bytes(range(256)) * 4

    put = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="assets/blob.bin",
        fileContent=binary_content,
    )
    blob_id = put["blobId"]

    blob = cc.get_blob(repositoryName=repo_name, blobId=blob_id)
    assert blob["content"] == binary_content, (
        f"blob content mismatch: got {len(blob['content'])} bytes, "
        f"expected {len(binary_content)} bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
