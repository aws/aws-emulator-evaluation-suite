"""put-file-unicode-content-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-file-unicode-content-round-trip"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A file written with multi-byte unicode content (emoji, CJK, combining
    marks) is returned unchanged byte-for-byte by GetFile."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-unicode-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "unicode-roundtrip"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    text = "héllo wörld \U0001F600 日本語 caf\u0065\u0301 combining-e\u0301 \u00f1\u00fc"
    content = text.encode("utf-8")

    cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="unicode.txt",
        fileContent=content,
    )

    got = cc.get_file(repositoryName=repo_name, filePath="unicode.txt")
    assert got["fileContent"] == content, (
        f"round-tripped bytes differ: got {got['fileContent']!r}, expected {content!r}"
    )
    assert got["fileContent"].decode("utf-8") == text, (
        f"decoded round-tripped content {got['fileContent'].decode('utf-8')!r} does not match "
        f"the original text {text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
