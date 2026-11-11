"""create-pull-request-missing-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-pull-request-missing-token-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePullRequest sent without a clientRequestToken (botocore's autofill handler is unregistered
    for that call) raises ClientRequestTokenRequiredException and opens no pull request, while the call
    with a token opens one."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cprt-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "cprt"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"init", filePath="README.md"
    )
    base_commit = put1["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)

    targets = [
        {"repositoryName": repo_name, "sourceReference": "feature", "destinationReference": "main"}
    ]

    before_ids = cc.list_pull_requests(repositoryName=repo_name)["pullRequestIds"]

    from botocore.handlers import generate_idempotent_uuid

    events = cc.meta.events
    events.unregister("before-parameter-build", generate_idempotent_uuid)
    try:
        code, message = _error(
            lambda: cc.create_pull_request(title="missing-token-pr", targets=targets)
        )
    finally:
        events.register("before-parameter-build", generate_idempotent_uuid)
    assert code == "ClientRequestTokenRequiredException", (
        f"expected ClientRequestTokenRequiredException for a truly absent token, got {code!r}"
    )
    expected = "A client request token is required."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_ids = cc.list_pull_requests(repositoryName=repo_name)["pullRequestIds"]
    assert after_ids == before_ids, "a pull request leaked despite the rejected request"

    # Positive control: the same call, letting botocore autofill the idempotency token
    # (i.e. leaving clientRequestToken unset entirely), succeeds normally.
    resp = cc.create_pull_request(title="missing-token-pr-ok", targets=targets)
    pr_id = resp["pullRequest"]["pullRequestId"]
    ctx.on_cleanup(
        lambda: cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
    )

    # Terminal assertion is an independent read (ListPullRequests), not the CreatePullRequest
    # response itself -- the created PR must actually be visible, open, at the destination.
    final_open_ids = cc.list_pull_requests(
        repositoryName=repo_name, pullRequestStatus="OPEN"
    )["pullRequestIds"]
    assert pr_id in final_open_ids, (
        f"{pr_id} missing from OPEN pull requests {final_open_ids!r} after a token-bearing "
        f"create_pull_request succeeded"
    )


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
