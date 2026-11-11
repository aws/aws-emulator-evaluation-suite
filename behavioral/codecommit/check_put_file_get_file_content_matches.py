"""put-file-get-file-content-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-file-get-file-content-matches"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Content written via PutFile is returned byte-identical by GetFile, including file mode."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "put-file-get-file"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    content = b"line one\nline two\nline three\n"
    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=content,
        filePath="hello.txt",
        fileMode="EXECUTABLE",
    )

    get_resp = cc.get_file(
        repositoryName=repo_name, commitSpecifier="main", filePath="hello.txt"
    )

    assert get_resp["fileContent"] == content, (
        f"fileContent mismatch: expected {content!r}, got {get_resp['fileContent']!r}"
    )
    assert get_resp["fileMode"] == "EXECUTABLE", (
        f"fileMode mismatch: expected EXECUTABLE, got {get_resp['fileMode']!r}"
    )
    assert get_resp["filePath"] == "hello.txt", (
        f"filePath mismatch: expected 'hello.txt', got {get_resp['filePath']!r}"
    )
    assert get_resp["fileSize"] == len(content), (
        f"fileSize mismatch: expected {len(content)}, got {get_resp['fileSize']!r}"
    )
    assert get_resp["commitId"] == put_resp["commitId"], (
        f"commitId mismatch: PutFile returned {put_resp['commitId']!r}, "
        f"GetFile returned {get_resp['commitId']!r}"
    )
    assert get_resp["blobId"] == put_resp["blobId"], (
        f"blobId mismatch: PutFile returned {put_resp['blobId']!r}, "
        f"GetFile returned {get_resp['blobId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
