"""commit-create-advances-branch-head."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "commit-create-advances-branch-head"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCommit on a branch advances the branch's HEAD commit id, observable via
    subsequent GetBranch/GetCommit calls, and the new commit's parent is the prior
    HEAD."""
    codecommit = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(repositoryName=repo_name, tags={"sim2real": "ccadv"})
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    # Bootstrap: first PutFile on an empty repo creates the initial commit + branch.
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"# hello\n",
        filePath="README.md",
    )
    first_commit = codecommit.get_branch(repositoryName=repo_name, branchName="main")["branch"]["commitId"]

    result = codecommit.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=first_commit,
        commitMessage="advance the branch head",
        putFiles=[{"filePath": "second.txt", "fileContent": b"second file content"}],
    )
    second_commit = result["commitId"]
    assert second_commit != first_commit, (
        f"CreateCommit returned the same commit id {second_commit!r} as the prior HEAD; "
        "the branch did not advance"
    )

    branch_after = codecommit.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch_after["commitId"] == second_commit, (
        f"branch HEAD is {branch_after['commitId']!r}, expected the new commit {second_commit!r}"
    )

    commit_details = codecommit.get_commit(repositoryName=repo_name, commitId=second_commit)["commit"]
    assert commit_details["commitId"] == second_commit, (
        f"GetCommit({second_commit!r}) returned commitId {commit_details['commitId']!r}"
    )
    assert commit_details["parents"] == [first_commit], (
        f"new commit's parents are {commit_details['parents']!r}, expected exactly [{first_commit!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
