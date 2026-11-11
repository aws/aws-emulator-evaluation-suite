"""unicode-file-content-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "unicode-file-content-round-trip"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A file committed with multi-byte UTF-8 content (accented Latin, CJK,
    emoji) is returned byte-identical by GetFile -- no re-encoding, escaping,
    or truncation of multi-byte sequences."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-unicode-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccuni"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    content = "héllo wörld 日本語 emoji:\U0001F600 Ω end".encode("utf-8")
    cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="unicode.txt",
        fileContent=content,
    )

    result = cc.get_file(repositoryName=repo_name, filePath="unicode.txt")
    assert isinstance(result["fileContent"], bytes), (
        f"expected fileContent to be bytes, got {type(result['fileContent'])!r}"
    )
    assert result["fileContent"] == content, (
        f"round-tripped bytes differ: got {result['fileContent']!r}, expected {content!r}"
    )
    assert result["fileContent"].decode("utf-8") == content.decode("utf-8"), (
        "round-tripped bytes no longer decode to the original unicode text"
    )
    assert result["fileSize"] == len(content), (
        f"fileSize {result['fileSize']} != actual byte length {len(content)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
