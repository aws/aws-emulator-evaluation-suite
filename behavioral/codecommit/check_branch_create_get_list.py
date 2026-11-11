"""branch-create-get-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "branch-create-get-list"
GROUP = 'lifecycle'
SERVICES = ['codecommit']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A branch workflow that needs only a repo: seed a first commit (PutFile),
    CreateBranch off that commit, GetBranch reflects it, ListBranches includes it."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccbcgl"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    name = meta["repositoryName"]
    commit_id = cc.put_file(repositoryName=name, branchName="main", fileContent=b"hello world", filePath="README.md", commitMessage="initial commit")["commitId"]

    branch = ctx.unique_name("sim2real-behav-branch-")
    cc.create_branch(
        repositoryName=name, branchName=branch, commitId=commit_id
    )

    got = cc.get_branch(repositoryName=name, branchName=branch)["branch"]
    assert got["branchName"] == branch, got
    assert got["commitId"] == commit_id, got

    branches = cc.list_branches(repositoryName=name)["branches"]
    assert branch in branches, branches

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
