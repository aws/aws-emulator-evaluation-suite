"""pull-request-status-lifecycle-transitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pull-request-status-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created pull request starts OPEN; UpdatePullRequestStatus transitions it to
    CLOSED, and GetPullRequest reflects the terminal state."""
    codecommit = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    codecommit.create_repository(
        repositoryName=repo_name, tags={"sim2real": "cc-pr-status-lifecycle-transitions"}
    )
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    # Bootstrap the repository: the first PutFile on an empty repo creates both the
    # initial commit and the default branch ("main").
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"# hello\n",
        filePath="README.md",
    )
    main_commit = codecommit.get_branch(repositoryName=repo_name, branchName="main")["branch"]["commitId"]

    # Create a feature branch off main, then diverge it so source != destination tips.
    codecommit.create_branch(repositoryName=repo_name, branchName="feature", commitId=main_commit)
    codecommit.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature work",
        filePath="feature.txt",
        parentCommitId=main_commit,
    )

    created = codecommit.create_pull_request(
        title=ctx.unique_name("sim2real-behav-pr-"),
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = created["pullRequestId"]
    created_status = created["pullRequestStatus"]
    assert created_status == "OPEN", f"expected a freshly created pull request to be OPEN, got {created_status!r}"

    fetched_open = codecommit.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    open_status = fetched_open["pullRequestStatus"]
    assert open_status == "OPEN", f"expected an independent read to confirm OPEN, got {open_status!r}"

    codecommit.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")

    fetched_closed = codecommit.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    closed_status = fetched_closed["pullRequestStatus"]
    assert closed_status == "CLOSED", (
        f"expected an independent read after UpdatePullRequestStatus to reflect CLOSED, got {closed_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
