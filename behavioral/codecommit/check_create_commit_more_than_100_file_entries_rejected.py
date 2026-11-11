"""create-commit-more-than-100-file-entries-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-commit-more-than-100-file-entries-rejected"
GROUP = "quotas"
SERVICES = ["codecommit"]

_LIMIT_MESSAGE = (
    "The commit cannot be created because it exceeds the maximum number of changed files "
    "allowed in a commit. The maximum limit for the number of files is 100 in the AWS "
    "CodeCommit console and in the CreateCommit API. Either create multiple commits to push "
    "these file changes, or use a Git client."
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _call(fn, *, budget_s: float = 60.0):
    """``fn()``, retrying only CodeCommit's ``ThrottlingException`` within a bounded budget."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _error(fn):
    """(code, message) of the error ``fn`` raises. An unexpected success raises too."""
    try:
        result = _call(fn)
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the commit to be refused, but it SUCCEEDED: {result!r}")


def _tip(cc, repo):
    return _call(lambda: cc.get_branch(repositoryName=repo, branchName="main"))["branch"]["commitId"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCommit counts puts and deletes together against a 100-file-entry ceiling: 101 new
    files, or 60 new plus 41 deletions, are refused with MaximumFileEntriesExceededException and
    leave the branch tip in place, while exactly 100 new files commit and advance it.
    """
    cc = ctx.client("codecommit")
    repo = ctx.unique_name("sim2real-behav-cc-max-")
    _call(lambda: cc.create_repository(repositoryName=repo, tags={"sim2real": CHECK}))
    ctx.on_cleanup(_teardown(lambda: cc.delete_repository(repositoryName=repo),
                             "RepositoryDoesNotExistException"))

    seed = _call(lambda: cc.create_commit(
        repositoryName=repo, branchName="main", commitMessage="seed 41 files",
        putFiles=[{"filePath": f"old/{i:03d}.txt", "fileContent": b"old"} for i in range(41)],
    ))["commitId"]
    assert _tip(cc, repo) == seed, "the seed commit did not become the branch tip"

    code, message = _error(lambda: cc.create_commit(
        repositoryName=repo, branchName="main", parentCommitId=seed,
        putFiles=[{"filePath": f"new/{i:03d}.txt", "fileContent": b"x"} for i in range(101)],
    ))
    assert code == "MaximumFileEntriesExceededException", f"101 puts were refused with {code!r}"
    assert message == _LIMIT_MESSAGE, f"101 puts were refused with message {message!r}"
    assert _tip(cc, repo) == seed, "a refused 101-file commit moved the branch tip"

    code, message = _error(lambda: cc.create_commit(
        repositoryName=repo, branchName="main", parentCommitId=seed,
        putFiles=[{"filePath": f"new/{i:03d}.txt", "fileContent": b"x"} for i in range(60)],
        deleteFiles=[{"filePath": f"old/{i:03d}.txt"} for i in range(41)],
    ))
    assert code == "MaximumFileEntriesExceededException", (
        f"60 puts + 41 deletes were refused with {code!r}")
    assert message == _LIMIT_MESSAGE, f"60 puts + 41 deletes were refused with message {message!r}"
    assert _tip(cc, repo) == seed, "a refused 60+41-entry commit moved the branch tip"

    ok = _call(lambda: cc.create_commit(
        repositoryName=repo, branchName="main", parentCommitId=seed, commitMessage="100 files",
        putFiles=[{"filePath": f"new/{i:03d}.txt", "fileContent": b"x"} for i in range(100)],
    ))
    added = sorted(f["absolutePath"] for f in ok["filesAdded"])
    assert added == [f"new/{i:03d}.txt" for i in range(100)], (
        f"the 100-file commit reported {len(added)} added files: {added[:3]!r}...")
    assert ok["filesDeleted"] == [], f"the 100-file commit reported deletions {ok['filesDeleted']!r}"
    assert _tip(cc, repo) == ok["commitId"], "the accepted 100-file commit did not advance the tip"
    parents = _call(lambda: cc.get_commit(repositoryName=repo, commitId=ok["commitId"]))["commit"]["parents"]
    assert parents == [seed], f"the 100-file commit's parents are {parents!r}, expected the seed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
