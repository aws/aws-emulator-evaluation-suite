"""batch-get-commits-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-commits-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetCommits called with more than the documented 100-commit-id limit
    raises CommitIdsLimitExceededException; a call at the limit succeeds and
    resolves every commit."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccbgc"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="initial commit",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello"}],
    )["commitId"]

    too_many = [commit1] * 101
    code, message = _error(lambda: cc.batch_get_commits(repositoryName=repo_name, commitIds=too_many))
    assert code == "CommitIdsLimitExceededException", f"unexpected code: {code}"
    expected_message = (
        "The operation cannot be completed because the number of requested "
        "commits exceeds the maximum allowed. The maximum number of commit IDs "
        "for BatchGetCommits is 100. Modify your request, and then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # positive control: at the 100-id boundary it succeeds and resolves the commit
    ok = cc.batch_get_commits(repositoryName=repo_name, commitIds=[commit1] * 100)
    assert ok["errors"] == [], f"expected no errors, got {ok['errors']}"
    assert len(ok["commits"]) == 1, (
        f"100 duplicate ids should dedupe to the single underlying commit, got {len(ok['commits'])}"
    )
    assert all(c["commitId"] == commit1 for c in ok["commits"]), (
        f"expected resolved commitId {commit1}, got {[c.get('commitId') for c in ok['commits']]}"
    )


def _error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
