"""commit-id-required-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "commit-id-required-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCommit with an empty commit id raises InvalidCommitIdException, distinct from the
    CommitIdDoesNotExistException for a well-formed absent id, while a real commit id resolves."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="initial commit",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello"}],
    )["commitId"]

    code, message = _error(lambda: cc.get_commit(repositoryName=repo_name, commitId=""))
    assert code == "InvalidCommitIdException", f"unexpected code: {code}"
    expected = "A commit ID is required, but the specified commit ID was empty or null."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a real commit id resolves fine
    got = cc.get_commit(repositoryName=repo_name, commitId=commit1)["commit"]
    assert got["commitId"] == commit1, f"expected {commit1}, got {got['commitId']}"

    # a well-formed but nonexistent commit id gets the DoesNotExist class instead
    bogus_id = "f" * 40
    code2, message2 = _error(
        lambda: cc.get_commit(repositoryName=repo_name, commitId=bogus_id)
    )
    assert code2 == "CommitIdDoesNotExistException", f"unexpected code: {code2}"
    expected2 = f"Could not retrieve {bogus_id}"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"
    assert code2 != code, "malformed and well-formed-but-absent ids must map to distinct error classes"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
