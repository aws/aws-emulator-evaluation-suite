"""merge-pull-request-concurrent-reference-update-conflict."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "merge-pull-request-concurrent-reference-update-conflict"
GROUP = "concurrency"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent fast-forward merges of the same pull request leave main on the feature commit
    and the pull request CLOSED and merged; at least one call succeeds, and a loser fails with an
    allowed conflict code (ConcurrentReferenceUpdateException with its exact message)."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-mpcruc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "mpcruc"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"init", filePath="README.md"
    )
    base_commit = put1["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)
    put2 = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"change",
        filePath="feature.txt",
        parentCommitId=base_commit,
    )
    feature_commit = put2["commitId"]

    targets = [
        {"repositoryName": repo_name, "sourceReference": "feature", "destinationReference": "main"}
    ]
    created = cc.create_pull_request(title="race-pr", targets=targets)
    pr_id = created["pullRequest"]["pullRequestId"]

    barrier = threading.Barrier(2)

    def _attempt_merge():
        barrier.wait(timeout=10)
        try:
            resp = cc.merge_pull_request_by_fast_forward(
                pullRequestId=pr_id, repositoryName=repo_name
            )
            return ("ok", resp)
        except Exception as exc:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", (exc.response["Error"]["Code"], exc.response["Error"]["Message"]))
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _attempt_merge(), range(2)))

    outcomes = [kind for kind, _ in results]

    # Two identical merges race: AWS either refuses one with a conflict/state error or answers
    # both with the same applied merge, so the end state is graded: main lands exactly once on
    # the feature commit and the pull request closes.
    allowed_error_codes = {
        "ConcurrentReferenceUpdateException",
        "PullRequestAlreadyClosedException",
        "ManualMergeRequiredException",
    }
    for kind, payload in results:
        if kind == "error":
            code, message = payload
            assert code in allowed_error_codes, f"unexpected loser error code: {payload}"
            if code == "ConcurrentReferenceUpdateException":
                expected = (
                    "The merge cannot be completed because the following branch has been modified: refs/heads/main. "
                    "Another user might have modified this branch while the merge was in progress. Wait a few "
                    "minutes, and then try again.")
                assert message == expected, f"the race loser must say {expected!r}, got {message!r}"
    assert outcomes.count("ok") >= 1, f"expected at least one winner, got {outcomes}"

    # The branch head must have advanced exactly to the merged commit -- never
    # corrupted, never left un-advanced, never advanced twice/past it.
    branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch["commitId"] == feature_commit, (
        f"main should have advanced exactly to {feature_commit!r}, got {branch['commitId']!r}"
    )

    final_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert final_pr["pullRequestStatus"] == "CLOSED", (
        f"expected pull request {pr_id} to be CLOSED after the race, "
        f"got {final_pr['pullRequestStatus']!r}"
    )
    merge_metadata = final_pr["pullRequestTargets"][0]["mergeMetadata"]
    assert merge_metadata["isMerged"] is True, f"expected isMerged True, got {merge_metadata!r}"
    assert merge_metadata["mergeCommitId"] == feature_commit, (
        f"expected mergeCommitId {feature_commit!r}, got {merge_metadata['mergeCommitId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
