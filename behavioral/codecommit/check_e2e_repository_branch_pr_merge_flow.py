"""e2e-repository-branch-pr-merge-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-repository-branch-pr-merge-flow"
GROUP = "e2e"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pull request merged by three-way merge closes and GetBranch on main returns the merge commit;
    after DeleteRepository reads and writes raise RepositoryDoesNotExistException."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-e2e-")

    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "e2e-repo-branch-pr-merge"})
    # Safety-net cleanup in case an assertion fails before the explicit delete
    # below; DeleteRepository is idempotent if already deleted.
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    c0 = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="README.md",
        fileContent=b"initial content",
    )["commitId"]

    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=c0)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="feature.txt",
        fileContent=b"feature work",
        parentCommitId=c0,
    )

    pr = cc.create_pull_request(
        title="e2e feature into main",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )
    pr_id = pr["pullRequest"]["pullRequestId"]

    merged = cc.merge_pull_request_by_three_way(
        pullRequestId=pr_id, repositoryName=repo_name
    )["pullRequest"]
    target = merged["pullRequestTargets"][0]
    assert target["mergeMetadata"]["isMerged"] is True, (
        f"expected isMerged True, got {target['mergeMetadata']}"
    )
    merge_commit_id = target["mergeMetadata"]["mergeCommitId"]
    assert merged["pullRequestStatus"] == "CLOSED", (
        f"expected pullRequestStatus CLOSED, got {merged['pullRequestStatus']}"
    )

    branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch["commitId"] == merge_commit_id, (
        f"expected main branch head {merge_commit_id}, got {branch['commitId']}"
    )

    # Explicit delete as the final step of the flow (cleanup above is idempotent).
    cc.delete_repository(repositoryName=repo_name)
    code, message = _error(lambda: cc.get_repository(repositoryName=repo_name))
    assert code == "RepositoryDoesNotExistException", code
    assert message == f"{repo_name} for {ctx.account}", message

    # A mutation against the now-dead repository must also fail, not just a read.
    mutate_code, mutate_message = _error(
        lambda: cc.create_branch(
            repositoryName=repo_name, branchName="post-delete", commitId=merge_commit_id
        )
    )
    assert mutate_code == "RepositoryDoesNotExistException", mutate_code
    assert mutate_message == f"{repo_name} for {ctx.account}", mutate_message


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
