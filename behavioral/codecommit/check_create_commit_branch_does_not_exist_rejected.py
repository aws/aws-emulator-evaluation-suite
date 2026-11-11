"""create-commit-branch-does-not-exist-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-commit-branch-does-not-exist-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCommit on a nonexistent branch raises BranchDoesNotExistException and creates no branch,
    while CreateCommit on the real branch advances its tip."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccbdne"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="README.md",
        fileContent=b"hello world",
    )
    main_tip = put["commitId"]

    ghost_branch = "ghost-branch-does-not-exist"
    code, message = _error(
        lambda: cc.create_commit(
            repositoryName=repo_name,
            branchName=ghost_branch,
            parentCommitId=main_tip,
            putFiles=[{"filePath": "new-file.txt", "fileContent": b"payload"}],
        )
    )
    assert code == "BranchDoesNotExistException", code
    expected = "The specified branch does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected call must not have created the branch as a side effect
    branches = cc.list_branches(repositoryName=repo_name)["branches"]
    assert ghost_branch not in branches, f"ghost branch leaked into {branches}"

    # positive control: CreateCommit against the real, current branch tip succeeds
    result = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=main_tip,
        putFiles=[{"filePath": "new-file.txt", "fileContent": b"payload"}],
    )
    assert result["commitId"] != main_tip, f"commit did not advance: still {main_tip}"
    new_tip = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]["commitId"]
    assert new_tip == result["commitId"], f"branch tip {new_tip} != committed id {result['commitId']}"


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
