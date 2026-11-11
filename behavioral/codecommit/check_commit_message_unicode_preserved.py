"""commit-message-unicode-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "commit-message-unicode-preserved"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A commit message containing unicode and newline characters supplied to
    CreateCommit is returned unmodified when the commit is fetched."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-msg-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-msg-unicode"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="a.txt",
        fileContent=b"v1",
    )
    parent_commit = put1["commitId"]

    message = "Fix bug \U0001F41B\nSecond line with caf\u00e9 and \u65e5\u672c\u8a9e\nThird line."

    commit = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=parent_commit,
        commitMessage=message,
        putFiles=[{"filePath": "b.txt", "fileContent": b"new file"}],
    )
    commit_id = commit["commitId"]

    got = cc.get_commit(repositoryName=repo_name, commitId=commit_id)
    assert got["commit"]["message"] == message, (
        f"commit message mismatch: got {got['commit']['message']!r}, expected {message!r}"
    )

    # A second independent read must return the identical bytes (no lazy re-encoding,
    # no drift between reads of the same stored commit).
    got_again = cc.get_commit(repositoryName=repo_name, commitId=commit_id)
    assert got_again["commit"]["message"] == message, (
        f"commit message changed on re-read: got {got_again['commit']['message']!r}, expected {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
