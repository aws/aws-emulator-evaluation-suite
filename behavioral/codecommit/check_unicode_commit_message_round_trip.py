"""unicode-commit-message-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "unicode-commit-message-round-trip"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A commit message with multi-byte unicode + emoji round-trips byte-equal via GetCommit."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "unicode-commit"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    unicode_message = (
        "Initial commit \U0001F389 with unicode: \u00e9\u00e8\u00ea "
        "\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8 \u00fcn\u00efc\u00f6d\u00e9 "
        "\u2603\ufe0f snowman and math \u2211\u222b\u2248"
    )

    create_resp = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello world"}],
        commitMessage=unicode_message,
    )
    commit_id = create_resp["commitId"]

    got = cc.get_commit(repositoryName=repo_name, commitId=commit_id)
    assert got["commit"]["message"] == unicode_message, (
        f"commit message mangled: expected {unicode_message!r}, got {got['commit']['message']!r}"
    )

    # A second independent read must return the exact same bytes (no lazy re-encoding).
    got_again = cc.get_commit(repositoryName=repo_name, commitId=commit_id)
    assert got_again["commit"]["message"] == unicode_message, (
        f"second read diverged: expected {unicode_message!r}, got {got_again['commit']['message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
