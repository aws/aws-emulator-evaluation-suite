"""concurrent-merge-to-same-branch-conflict-detected."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-merge-to-same-branch-conflict-detected"
GROUP = "concurrency"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two pull requests fast-forward-merged concurrently into the same main tip yield exactly one merge;
    the loser is refused with the exact message and main ends at the winner's source tip."""
    cc = ctx.client("codecommit")
    repo = _create_repo(ctx)

    base_commit = _put_file(ctx, repo, "main", "base.txt", b"root\n", parent_commit_id=None)

    cc.create_branch(repositoryName=repo, branchName="feature-a", commitId=base_commit)
    commit_a = _put_file(
        ctx, repo, "feature-a", "a.txt", b"branch a work\n", parent_commit_id=base_commit
    )

    cc.create_branch(repositoryName=repo, branchName="feature-b", commitId=base_commit)
    commit_b = _put_file(
        ctx, repo, "feature-b", "b.txt", b"branch b work\n", parent_commit_id=base_commit
    )

    pr_a = cc.create_pull_request(
        title="concurrent ff merge race A",
        targets=[
            {
                "repositoryName": repo,
                "sourceReference": "feature-a",
                "destinationReference": "main",
            }
        ],
    )
    pr_a_id = pr_a["pullRequest"]["pullRequestId"]

    pr_b = cc.create_pull_request(
        title="concurrent ff merge race B",
        targets=[
            {
                "repositoryName": repo,
                "sourceReference": "feature-b",
                "destinationReference": "main",
            }
        ],
    )
    pr_b_id = pr_b["pullRequest"]["pullRequestId"]

    barrier = threading.Barrier(2)

    def _attempt_merge(pr_id):
        barrier.wait(timeout=10)
        return cc.merge_pull_request_by_fast_forward(pullRequestId=pr_id, repositoryName=repo)

    successes = []
    failures = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_attempt_merge, pid) for pid in (pr_a_id, pr_b_id)]
        for fut in futures:
            try:
                successes.append(fut.result())
            except ClientError as exc:
                failures.append((exc.response["Error"]["Code"], exc.response["Error"]["Message"]))

    assert len(successes) == 1, (
        f"expected exactly one of the two racing merges to succeed, got {len(successes)} "
        f"successes and failures={failures}"
    )
    assert len(failures) == 1, f"expected exactly one racing merge to fail, got {failures}"
    acceptable_loser_codes = {
        "ConcurrentReferenceUpdateException",
        "ManualMergeRequiredException",
        "TipsDivergenceExceededException",
    }
    loser_code, loser_message = failures[0]
    assert loser_code in acceptable_loser_codes, (
        f"loser of the merge race should get a race/ff-conflict error, got {failures[0]}"
    )
    if loser_code == "ConcurrentReferenceUpdateException":
        expected = (
            "The merge cannot be completed because the following branch has been modified: refs/heads/main. "
            "Another user might have modified this branch while the merge was in progress. Wait a few "
            "minutes, and then try again.")
        assert loser_message == expected, f"the race loser must say {expected!r}, got {loser_message!r}"

    winner_pr = successes[0]["pullRequest"]
    target = winner_pr["pullRequestTargets"][0]
    assert target["mergeMetadata"]["isMerged"] is True
    assert winner_pr["pullRequestStatus"] == "CLOSED"
    expected_tip = target["mergeMetadata"]["mergeCommitId"]
    assert expected_tip in (commit_a, commit_b), (
        f"winner's own reported merge commit should be one of the two source tips, "
        f"got {expected_tip}"
    )

    final_tip = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert final_tip == expected_tip, (
        f"destination branch should land exactly on the winner's own reported merge "
        f"commit {expected_tip}, got {final_tip}"
    )


def _create_repo(ctx) -> str:
    cc = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-ccrepo-")
    cc.create_repository(repositoryName=name, tags={"sim2real": "ccmergerace"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))
    return name


def _put_file(ctx, repo: str, branch: str, path: str, content: bytes, parent_commit_id):
    cc = ctx.client("codecommit")
    kwargs = {
        "repositoryName": repo,
        "branchName": branch,
        "fileContent": content,
        "filePath": path,
    }
    if parent_commit_id is not None:
        kwargs["parentCommitId"] = parent_commit_id
    resp = cc.put_file(**kwargs)
    return resp["commitId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
