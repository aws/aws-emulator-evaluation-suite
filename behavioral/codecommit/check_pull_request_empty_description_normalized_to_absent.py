"""pull-request-empty-description-normalized-to-absent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pull-request-empty-description-normalized-to-absent"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pull request created without a description reads back with none, and so does each update
    to "", while an update to "not empty" reads back as given: CodeCommit normalizes "" to absent."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cc-pr-empty-desc"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put_resp = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"line one\n",
        filePath="a.txt",
    )
    tip_commit = put_resp["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=tip_commit)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"line one\nline two\n",
        filePath="a.txt",
        parentCommitId=tip_commit,
    )

    created = cc.create_pull_request(
        title="No description provided",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )
    pr_id = created["pullRequest"]["pullRequestId"]
    ctx.on_cleanup(lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED"))

    # No description was supplied at creation time: it must read back as ABSENT (None).
    fetched_absent = cc.get_pull_request(pullRequestId=pr_id)
    assert fetched_absent["pullRequest"].get("description") is None, (
        f"expected description to be absent, got {fetched_absent['pullRequest'].get('description')!r}"
    )

    # Explicitly setting it to "" is normalized to absent: CodeCommit does not preserve "" as a
    # value distinct from an unset description.
    cc.update_pull_request_description(pullRequestId=pr_id, description="")
    fetched_empty = cc.get_pull_request(pullRequestId=pr_id)
    assert fetched_empty["pullRequest"].get("description") is None, (
        f"expected empty-string description to normalize to absent (None), "
        f"got {fetched_empty['pullRequest'].get('description')!r}"
    )

    # A genuinely non-empty description IS preserved and distinguishable from both above.
    cc.update_pull_request_description(pullRequestId=pr_id, description="not empty")
    fetched_nonempty = cc.get_pull_request(pullRequestId=pr_id)
    assert fetched_nonempty["pullRequest"].get("description") == "not empty", (
        f"expected non-empty description to round-trip verbatim, "
        f"got {fetched_nonempty['pullRequest'].get('description')!r}"
    )

    # And going back to "" collapses to absent (None) again, not to the string "" nor to
    # the previous non-empty value.
    cc.update_pull_request_description(pullRequestId=pr_id, description="")
    fetched_empty_again = cc.get_pull_request(pullRequestId=pr_id)
    assert fetched_empty_again["pullRequest"].get("description") is None, (
        f"expected description to normalize back to absent (None), "
        f"got {fetched_empty_again['pullRequest'].get('description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

