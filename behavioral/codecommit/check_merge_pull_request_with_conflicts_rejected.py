"""merge-pull-request-with-conflicts-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-pull-request-with-conflicts-rejected"
GROUP = "data-plane"
SERVICES = ["codecommit"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergePullRequestBySquash on a conflicting PR is rejected with ManualMergeRequiredException,
    leaves the PR OPEN and destination branch untouched; a non-conflicting PR merges fine."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccmerge"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"base\n",
        filePath="conflict.txt",
        commitMessage="base",
    )
    base_commit = base["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    main_after = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"changed on main\n",
        filePath="conflict.txt",
        parentCommitId=base_commit,
        commitMessage="change on main",
    )
    main_tip_before = main_after["commitId"]

    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"changed on feature\n",
        filePath="conflict.txt",
        parentCommitId=base_commit,
        commitMessage="change on feature",
    )

    pr = cc.create_pull_request(
        title=ctx.unique_name("sim2real-pr-"),
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]
    ctx.on_cleanup(lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED"))

    # Break exactly one thing: attempt an automatic squash merge of a genuinely conflicting PR.
    code, message = _error(
        lambda: cc.merge_pull_request_by_squash(pullRequestId=pr_id, repositoryName=repo_name)
    )
    assert code == "ManualMergeRequiredException", f"expected ManualMergeRequiredException, got {code!r}"
    assert message == (
        "Current branches cannot be merged, please try to merge using a Git client locally."
    ), message

    # Effect absent: PR still OPEN, and main's tip has not moved.
    pr_after = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert pr_after["pullRequestStatus"] == "OPEN", (
        f"expected pull request to remain OPEN after a rejected merge, got {pr_after['pullRequestStatus']!r}"
    )
    branch_after = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch_after["commitId"] == main_tip_before, (
        f"expected main's tip to stay at {main_tip_before!r} after a rejected merge, "
        f"got {branch_after['commitId']!r}"
    )

    # Positive control: a second, non-conflicting PR against the same repo merges cleanly.
    cc.create_branch(repositoryName=repo_name, branchName="feature2", commitId=main_tip_before)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature2",
        fileContent=b"unrelated addition\n",
        filePath="unrelated.txt",
        parentCommitId=main_tip_before,
        commitMessage="unrelated addition",
    )
    pr2 = cc.create_pull_request(
        title=ctx.unique_name("sim2real-pr2-"),
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature2",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr2_id = pr2["pullRequestId"]
    merged = cc.merge_pull_request_by_squash(pullRequestId=pr2_id, repositoryName=repo_name)
    assert merged["pullRequest"]["pullRequestStatus"] == "CLOSED", (
        f"expected the non-conflicting merge to close the pull request, "
        f"got {merged['pullRequest']['pullRequestStatus']!r}"
    )

    # Independent read at the destination, through calls other than the one that merged:
    # the pull request shows CLOSED and main's tip actually advanced.
    pr2_after = cc.get_pull_request(pullRequestId=pr2_id)["pullRequest"]
    assert pr2_after["pullRequestStatus"] == "CLOSED", (
        f"expected an independent read to also show CLOSED, got {pr2_after['pullRequestStatus']!r}"
    )
    branch_final = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch_final["commitId"] != main_tip_before, (
        f"expected the non-conflicting merge to advance main's tip past {main_tip_before!r}, "
        "but it did not move"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
