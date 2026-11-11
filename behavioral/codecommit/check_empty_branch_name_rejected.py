"""empty-branch-name-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "empty-branch-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCommit and DeleteFile with an empty branchName raise InvalidBranchNameException "Branch name
    cannot be empty", while the real branch name works for both."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccebn"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="initial commit",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello"}],
    )["commitId"]

    # An explicit "" is a malformed name (InvalidBranchNameException), not a missing one
    # (BranchNameRequiredException); client-side validation (min length 1) is off so the
    # request reaches the service.
    unvalidated = ctx.client("codecommit", config=Config(parameter_validation=False))
    code, message = _error(lambda: unvalidated.create_commit(
        repositoryName=repo_name,
        branchName="",
        parentCommitId=commit1,
        putFiles=[{"filePath": "second.txt", "fileContent": b"x"}],
    ))
    assert code == "InvalidBranchNameException", f"unexpected code: {code}"
    assert message == "Branch name cannot be empty", message

    # DeleteFile with an empty branch name raises the same malformed-name error.
    code2, message2 = _error(lambda: unvalidated.delete_file(
        repositoryName=repo_name,
        branchName="",
        filePath="README.md",
        parentCommitId=commit1,
    ))
    assert code2 == "InvalidBranchNameException", f"unexpected code: {code2}"
    assert message2 == "Branch name cannot be empty", message2

    # effect absent: main's tip is unchanged, no stray commit/branch was created
    branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch["commitId"] == commit1, (
        f"expected main tip unchanged at {commit1!r}, got {branch['commitId']!r}")

    # positive control: a real branch name succeeds and advances the tip
    commit2 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=commit1,
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="second commit",
        putFiles=[{"filePath": "second.txt", "fileContent": b"world"}],
    )["commitId"]
    branch2 = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch2["commitId"] == commit2 != commit1, (
        f"expected main tip to advance to {commit2!r} (from {commit1!r}), got {branch2['commitId']!r}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an empty branch name real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected InvalidBranchNameException, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
