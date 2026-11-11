"""deploy-codecommit-repository-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-codecommit-repository-behaves"
GROUP = "deploy"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A repository deployed via CloudFormation actually accepts branch creation and
    file writes/reads, not merely reaching CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    codecommit = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cfn-repo-")
    stack_name = ctx.unique_name("sim2real-cfn-stack-")

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Repo": {
                    "Type": "AWS::CodeCommit::Repository",
                    "Properties": {
                        "RepositoryName": repo_name,
                        "RepositoryDescription": "sim2real behavioral fidelity check repo",
                    },
                }
            },
            "Outputs": {"RepoName": {"Value": {"Ref": "Repo"}}},
        }
    )

    def _cleanup_stack():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    ctx.on_cleanup(_cleanup_stack)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"unexpected stack status {status}"

    # The repository must be a real, usable CodeCommit repo, not just a control-plane
    # record: verify it exists via the data API, then exercise branch/file operations.
    repo_meta = codecommit.get_repository(repositoryName=repo_name)["repositoryMetadata"]
    assert repo_meta["repositoryName"] == repo_name, (
        f"expected repositoryName {repo_name!r}, got {repo_meta['repositoryName']!r}"
    )
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    put_resp = codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"hello from sim2real\n",
        filePath="README.md",
        commitMessage="initial commit",
        name="sim2real",
        email="sim2real@example.com",
    )
    main_commit_id = put_resp["commitId"]

    codecommit.create_branch(
        repositoryName=repo_name, branchName="feature", commitId=main_commit_id
    )
    feature_branch = codecommit.get_branch(repositoryName=repo_name, branchName="feature")["branch"]
    assert feature_branch["commitId"] == main_commit_id, (
        f"expected feature branch head {main_commit_id!r}, got {feature_branch['commitId']!r}"
    )

    file_resp = codecommit.get_file(repositoryName=repo_name, filePath="README.md")
    assert file_resp["fileContent"] == b"hello from sim2real\n", (
        f"expected README.md content b'hello from sim2real\\n', got {file_resp['fileContent']!r}"
    )
    assert file_resp["commitId"] == main_commit_id, (
        f"expected get_file commitId {main_commit_id!r}, got {file_resp['commitId']!r}"
    )

    # Branch listing must converge to include both branches before teardown deletes
    # the repo -- poll the observable condition instead of sleeping a fixed amount.
    _poll_until(
        lambda: set(codecommit.list_branches(repositoryName=repo_name)["branches"]),
        lambda branches: {"main", "feature"} <= branches,
        timeout_s=20.0,
        interval_s=1.0,
        description="list_branches to include both 'main' and 'feature'",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description}; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
