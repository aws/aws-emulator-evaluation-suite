"""put-file-on-nonexistent-branch-blocked."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-file-on-nonexistent-branch-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """In a repository with commits, PutFile on a nonexistent branch raises BranchDoesNotExistException
    and creates no branch, while PutFile on the real branch advances its tip."""
    codecommit = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name, tags={"sim2real": "ccnobranch"})
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    # Seed the repository: on an empty repo, PutFile is allowed to create the branch.
    seed = codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=base64.b64encode(b"seed content").decode(),
        filePath="README.md",
        commitMessage="seed commit",
    )
    seed_commit_id = seed["commitId"]

    # Now the repo is non-empty: PutFile against a never-created branch must be rejected.
    ghost_branch = ctx.unique_name("sim2real-behav-ghost-branch-")
    code, message = _error(
        lambda: codecommit.put_file(
            repositoryName=repo_name,
            branchName=ghost_branch,
            fileContent=base64.b64encode(b"should not land").decode(),
            filePath="ghost.txt",
            commitMessage="should be rejected",
        )
    )
    assert code == "BranchDoesNotExistException", (
        f"expected BranchDoesNotExistException, got {code!r}"
    )
    assert message == "The specified branch does not exist", (
        f"expected message 'The specified branch does not exist', got {message!r}"
    )

    # Effect absent: the ghost branch was never created.
    branches = codecommit.list_branches(repositoryName=repo_name)["branches"]
    assert ghost_branch not in branches, (
        f"expected {ghost_branch!r} absent from branches, found it in {branches!r}"
    )

    # Positive control: PutFile against the existing "main" branch succeeds.
    good = codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=base64.b64encode(b"real update").decode(),
        filePath="real.txt",
        parentCommitId=seed_commit_id,
        commitMessage="real update lands",
    )
    assert good["commitId"] != seed_commit_id, (
        f"expected a new commitId distinct from seed {seed_commit_id!r}, got {good['commitId']!r}"
    )
    tip = codecommit.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert tip["commitId"] == good["commitId"], (
        f"expected main tip {good['commitId']!r}, got {tip['commitId']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
