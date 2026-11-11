"""get-commit-unknown-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-commit-unknown-id-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCommit with a syntactically valid but unknown commit id fails with
    CommitIdDoesNotExistException, and GetCommit with the real commit id in
    the same repository still succeeds (positive control)."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-ccgc-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="a.txt",
        fileContent=b"x",
    )
    commit_id = put["commitId"]
    assert len(commit_id) == 40, f"expected a 40-char git SHA1 commit id, got {commit_id!r}"

    # flip the last hex character to build a syntactically-valid, unknown 40-char SHA
    last = commit_id[-1]
    flipped = "0" if last != "0" else "1"
    fake_id = commit_id[:-1] + flipped
    assert fake_id != commit_id, f"flipped id must differ from the real one, both were {fake_id!r}"

    code, message = _error(lambda: cc.get_commit(repositoryName=repo_name, commitId=fake_id))
    assert code == "CommitIdDoesNotExistException", (
        f"expected CommitIdDoesNotExistException for unknown id {fake_id!r}, got {code!r}"
    )
    assert message == f"Could not retrieve {fake_id}", message

    # positive control: the real commit id resolves correctly
    result = cc.get_commit(repositoryName=repo_name, commitId=commit_id)
    assert result["commit"]["commitId"] == commit_id, (
        f"expected GetCommit to resolve the real commit id {commit_id!r}, "
        f"got {result['commit']['commitId']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
