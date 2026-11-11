"""update-pull-request-title-after-close-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-pull-request-title-after-close-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a PR is CLOSED, UpdatePullRequestTitle and UpdatePullRequestDescription raise
    PullRequestAlreadyClosedException and leave the title and description unchanged."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-uprtc-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"init", filePath="README.md"
    )
    base_commit = put1["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    targets = [
        {"repositoryName": repo_name, "sourceReference": "feature", "destinationReference": "main"}
    ]
    created = cc.create_pull_request(
        title="Original title", description="Original description", targets=targets
    )
    pr_id = created["pullRequest"]["pullRequestId"]

    # Positive control: updating the title while the PR is still OPEN succeeds.
    updated = cc.update_pull_request_title(pullRequestId=pr_id, title="Updated while open")
    assert updated["pullRequest"]["title"] == "Updated while open", (
        f"expected title 'Updated while open' on an OPEN pull request, got "
        f"{updated['pullRequest']['title']!r}"
    )

    cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
    closed = cc.get_pull_request(pullRequestId=pr_id)
    assert closed["pullRequest"]["pullRequestStatus"] == "CLOSED", (
        f"expected pullRequestStatus CLOSED after UpdatePullRequestStatus, got "
        f"{closed['pullRequest']['pullRequestStatus']!r}"
    )

    title_code, title_message = _error(
        lambda: cc.update_pull_request_title(pullRequestId=pr_id, title="Should be rejected")
    )
    assert title_code == "PullRequestAlreadyClosedException", (
        f"expected UpdatePullRequestTitle on a CLOSED pull request to raise "
        f"PullRequestAlreadyClosedException, got {title_code!r}"
    )
    expected_message = (
        "The change cannot be made because the state of the pull request is CLOSED. "
        "You cannot update the title or description of a pull request after it has "
        "been closed."
    )
    assert title_message == expected_message, (
        f"expected UpdatePullRequestTitle's message {expected_message!r}, got {title_message!r}"
    )

    description_code, description_message = _error(
        lambda: cc.update_pull_request_description(
            pullRequestId=pr_id, description="Should be rejected"
        )
    )
    assert description_code == "PullRequestAlreadyClosedException", (
        f"expected UpdatePullRequestDescription on a CLOSED pull request to raise "
        f"PullRequestAlreadyClosedException, got {description_code!r}"
    )
    assert description_message == expected_message, (
        f"expected UpdatePullRequestDescription's message {expected_message!r}, got "
        f"{description_message!r}"
    )

    # Effect absent: neither the title nor the description changed after closure.
    final = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert final["title"] == "Updated while open", (
        f"title changed after the rejected UpdatePullRequestTitle call: {final['title']!r}"
    )
    assert final["description"] == "Original description", (
        f"description changed after the rejected UpdatePullRequestDescription call: "
        f"{final['description']!r}"
    )
    assert final["pullRequestStatus"] == "CLOSED", (
        f"expected pullRequestStatus to remain CLOSED, got {final['pullRequestStatus']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected a ClientError but the call succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
