"""branch-delete-then-get-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "branch-delete-then-get-not-found"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteBranch, GetBranch and a PutFile on the name raise BranchDoesNotExistException, the
    name leaves ListBranches, and CreateBranch can reuse it."""
    codecommit = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    # Bootstrap: first PutFile on an empty repo creates the initial commit and the
    # default branch "main" -- this becomes the repository's un-deletable default.
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"# hello\n",
        filePath="README.md",
    )
    main_commit = codecommit.get_branch(repositoryName=repo_name, branchName="main")["branch"]["commitId"]

    branch_name = "feature-to-delete"
    codecommit.create_branch(repositoryName=repo_name, branchName=branch_name, commitId=main_commit)

    # Positive control: the branch is visible before deletion.
    before = codecommit.get_branch(repositoryName=repo_name, branchName=branch_name)["branch"]
    assert before["branchName"] == branch_name, (
        f"expected the newly created branch {branch_name!r} to be visible, got {before!r}"
    )

    codecommit.delete_branch(repositoryName=repo_name, branchName=branch_name)

    # Beat 1: an independent read (GetBranch, not DeleteBranch's own response) returns
    # the specific not-found code.
    code, message = _error(
        lambda: codecommit.get_branch(repositoryName=repo_name, branchName=branch_name)
    )
    assert code == "BranchDoesNotExistException", (
        f"expected GetBranch on a deleted branch to raise BranchDoesNotExistException, got {code!r}"
    )
    # GetBranch on a missing branch carries an empty message on real AWS.
    expected_message = ""
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Beat 2: a second independent observable -- the name has also dropped out of the list.
    remaining = codecommit.list_branches(repositoryName=repo_name)["branches"]
    assert branch_name not in remaining, (
        f"deleted branch {branch_name!r} must not still appear in ListBranches, got {remaining!r}"
    )

    # Beat 3: a mutation targeting the dead name is also rejected -- not just reads.
    put_code, put_message = _error(
        lambda: codecommit.put_file(
            repositoryName=repo_name,
            branchName=branch_name,
            fileContent=b"should not land",
            filePath="ghost.txt",
        )
    )
    assert put_code == "BranchDoesNotExistException", (
        f"expected PutFile against a deleted branch to raise BranchDoesNotExistException, got {put_code!r}"
    )
    expected_message = "The specified branch does not exist"
    assert put_message == expected_message, (
        f"expected message {expected_message!r}, got {put_message!r}"
    )

    # Beat 4: the name is reusable once dead -- CodeCommit does not tombstone branch names.
    codecommit.create_branch(repositoryName=repo_name, branchName=branch_name, commitId=main_commit)
    reused = codecommit.get_branch(repositoryName=repo_name, branchName=branch_name)["branch"]
    assert reused["commitId"] == main_commit, (
        f"expected the reused branch name {branch_name!r} to point at {main_commit!r}, got {reused!r}"
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
