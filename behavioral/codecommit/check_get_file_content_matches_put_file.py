"""get-file-content-matches-put-file."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-file-content-matches-put-file"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetFile against a specific commit returns the same content, size, and mode PutFile wrote."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccgetfile"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    content = b"#!/bin/sh\necho hello-from-sim2real\n"
    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=content,
        filePath="scripts/run.sh",
        fileMode="EXECUTABLE",
        commitMessage="add executable script",
    )
    commit_id = put_resp["commitId"]
    blob_id = put_resp["blobId"]

    file_resp = cc.get_file(
        repositoryName=repo_name, commitSpecifier=commit_id, filePath="scripts/run.sh"
    )

    got_content = file_resp["fileContent"]
    if hasattr(got_content, "read"):
        got_content = got_content.read()

    assert got_content == content, (
        f"GetFile content mismatch: expected {content!r}, got {got_content!r}"
    )
    assert file_resp["fileMode"] == "EXECUTABLE", (
        f"expected fileMode EXECUTABLE, got {file_resp['fileMode']!r}"
    )
    assert file_resp["fileSize"] == len(content), (
        f"expected fileSize {len(content)}, got {file_resp['fileSize']!r}"
    )
    assert file_resp["blobId"] == blob_id, (
        f"expected blobId {blob_id!r} (from PutFile), got {file_resp['blobId']!r}"
    )
    assert file_resp["commitId"] == commit_id, (
        f"expected commitId {commit_id!r} (from PutFile), got {file_resp['commitId']!r}"
    )
    assert file_resp["filePath"] == "scripts/run.sh", (
        f"expected filePath 'scripts/run.sh', got {file_resp['filePath']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
