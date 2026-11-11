"""deploy-codecommit-repository-behaves-after-stack-create."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-codecommit-repository-behaves-after-stack-create"
GROUP = "deploy"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A repository provisioned via an AWS::CodeCommit::Repository CloudFormation stack
    accepts PutFile/CreateBranch calls and GetRepository reflects the stack-defined
    name/description."""
    repo_name = ctx.unique_name("sim2real-behav-repo-")
    description = "sim2real behavioral fidelity test repository"
    template = {
        "Resources": {
            "Repo": {
                "Type": "AWS::CodeCommit::Repository",
                "Properties": {
                    "RepositoryName": repo_name,
                    "RepositoryDescription": description,
                },
            }
        },
        "Outputs": {"RepoName": {"Value": {"Ref": "Repo"}}},
    }
    _deploy_cfn(ctx, template)

    codecommit = ctx.client("codecommit")

    # GetRepository reflects the stack-defined name/description
    repo = codecommit.get_repository(repositoryName=repo_name)["repositoryMetadata"]
    assert repo["repositoryName"] == repo_name, (
        f"expected repositoryName={repo_name!r}, got {repo['repositoryName']!r}"
    )
    assert repo["repositoryDescription"] == description, (
        f"expected repositoryDescription={description!r}, got {repo['repositoryDescription']!r}"
    )

    # A fresh CFN-created repository has no branches until the first commit; PutFile
    # creates that first commit (and, since the repo is empty, the "main" branch too).
    put_result = codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"hello from sim2real\n",
        filePath="README.md",
    )
    first_commit_id = put_result["commitId"]

    # CreateBranch from the commit created by PutFile
    codecommit.create_branch(
        repositoryName=repo_name, branchName="feature", commitId=first_commit_id
    )
    branch = codecommit.get_branch(repositoryName=repo_name, branchName="feature")["branch"]
    assert branch["branchName"] == "feature", (
        f"expected branchName='feature', got {branch['branchName']!r}"
    )
    assert branch["commitId"] == first_commit_id, (
        f"expected feature branch commitId={first_commit_id!r}, got {branch['commitId']!r}"
    )

    # GetFile on the new branch returns exactly the content committed via PutFile
    file_resp = codecommit.get_file(
        repositoryName=repo_name, commitSpecifier="feature", filePath="README.md"
    )
    assert file_resp["fileContent"] == b"hello from sim2real\n", (
        f"expected fileContent=b'hello from sim2real\\n', got {file_resp['fileContent']!r}"
    )
    assert file_resp["commitId"] == first_commit_id, (
        f"expected GetFile commitId={first_commit_id!r}, got {file_resp['commitId']!r}"
    )


def _deploy_cfn(ctx, template: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": "deploy-codecommit-repository-behaves-after-stack-create"}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return stack_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
