"""commit-create-then-get-chain."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "commit-create-then-get-chain"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCommit against a branch produces a commit whose parent chain and branch tip are correct."""
    cc = ctx.client("codecommit")
    repo_name = _create_repo(ctx)

    first_commit_id = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        putFiles=[{"filePath": "a.txt", "fileContent": b"first"}],
        commitMessage="first commit",
    )["commitId"]

    second_commit_id = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        parentCommitId=first_commit_id,
        putFiles=[{"filePath": "b.txt", "fileContent": b"second"}],
        commitMessage="second commit",
    )["commitId"]
    assert second_commit_id != first_commit_id, (
        f"second CreateCommit returned the same commitId {second_commit_id!r} as the first"
    )

    second_commit = cc.get_commit(repositoryName=repo_name, commitId=second_commit_id)["commit"]
    assert second_commit["parents"] == [first_commit_id], (
        f"GetCommit({second_commit_id}) parents {second_commit['parents']!r}, "
        f"expected exactly [{first_commit_id!r}]"
    )

    first_commit = cc.get_commit(repositoryName=repo_name, commitId=first_commit_id)["commit"]
    # `parents` is not a required member, so an absent key and an empty list both mean
    # "no parents"; anything else is wrong for the root commit.
    assert first_commit.get("parents", []) == [], (
        f"the root commit reports parents {first_commit.get('parents')!r}, expected none"
    )

    branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch["commitId"] == second_commit_id, (
        f"GetBranch(main) commitId {branch['commitId']!r}, expected {second_commit_id!r}"
    )
    assert branch["branchName"] == "main", f"GetBranch(main) branchName {branch['branchName']!r}"


def _create_repo(ctx) -> str:
    cc: Any = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-repo-")
    cc.create_repository(repositoryName=name, tags={"sim2real": "commit-create-then-get-chain"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
