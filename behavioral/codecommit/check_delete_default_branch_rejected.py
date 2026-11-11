"""delete-default-branch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "delete-default-branch-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codecommit']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBranch on the default branch raises DefaultBranchCannotBeDeletedException and leaves it in
    place, while a non-default branch deletes; after UpdateDefaultBranch the identical delete succeeds."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(repositoryName=ctx.unique_name("sim2real-behav-repo-"))["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    name = meta["repositoryName"]
    main_commit = cc.put_file(repositoryName=name, branchName="main", fileContent=b"hello world", filePath="README.md", commitMessage="initial commit")["commitId"]

    # The first commit sets the default branch; read it back to be exact.
    default = cc.get_repository(repositoryName=name)["repositoryMetadata"].get(
        "defaultBranch"
    )
    if not default:
        raise AssertionError("repository has no default branch after first commit")

    # Positive control: DeleteBranch works at all, on a branch that is not the default.
    cc.create_branch(repositoryName=name, branchName="side", commitId=main_commit)
    cc.delete_branch(repositoryName=name, branchName="side")
    code, message = _error(lambda: cc.get_branch(repositoryName=name, branchName="side"))
    assert code == "BranchDoesNotExistException", code
    # GetBranch answers a missing branch with an empty message.
    assert message == "", f"expected an empty message, got {message!r}"

    # Break: the same call, against the default branch, must be refused.
    code, message = _error(lambda: cc.delete_branch(repositoryName=name, branchName=default))
    assert code == "DefaultBranchCannotBeDeletedException", code
    expected = f"The current default branch refs/heads/{default} cannot be deleted"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read shows the default branch untouched.
    still_there = cc.get_branch(repositoryName=name, branchName=default)["branch"]
    assert still_there["commitId"] == main_commit, still_there["commitId"]

    # Restore: repoint the default elsewhere, then the identical DeleteBranch succeeds.
    cc.create_branch(repositoryName=name, branchName="new-default", commitId=main_commit)
    cc.update_default_branch(repositoryName=name, defaultBranchName="new-default")
    cc.delete_branch(repositoryName=name, branchName=default)
    code, message = _error(lambda: cc.get_branch(repositoryName=name, branchName=default))
    assert code == "BranchDoesNotExistException", code
    assert message == "", f"expected an empty message, got {message!r}"


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
