"""merge-of-a-closed-pull-request-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-of-a-closed-pull-request-rejected"
GROUP = 'error-semantics'
SERVICES = ['codecommit']


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Merging a pull request whose status was set to CLOSED is refused with
    PullRequestAlreadyClosedException and the destination branch does not move, while a
    second pull request over the identical branch pair merges cleanly."""
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-ccclosed-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccclosed"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    feature_body = b"added on the feature branch\n"
    main_tip = cc.put_file(repositoryName=repo, branchName="main", filePath="base.txt",
                           fileContent=b"base\n", commitMessage="base")["commitId"]
    cc.create_branch(repositoryName=repo, branchName="feature", commitId=main_tip)
    feature_tip = cc.put_file(repositoryName=repo, branchName="feature",
                              filePath="feature.txt", fileContent=feature_body,
                              parentCommitId=main_tip,
                              commitMessage="feature work")["commitId"]

    targets = [{"repositoryName": repo, "sourceReference": "feature",
                "destinationReference": "main"}]
    opened = cc.create_pull_request(title="closed-then-merged", targets=targets)["pullRequest"]
    pr_id = opened["pullRequestId"]
    assert opened["pullRequestStatus"] == "OPEN", (
        f"a new pull request reports status {opened['pullRequestStatus']!r}, expected 'OPEN'"
    )

    # Break exactly one thing: close it. Everything else -- the branches, the diff, the
    # absence of approval rules -- is untouched.
    cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")
    reread = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert reread["pullRequestStatus"] == "CLOSED", (
        f"after update_pull_request_status the pull request reports "
        f"{reread['pullRequestStatus']!r}, expected 'CLOSED' -- the barrier for the refusal"
    )

    code, message = _error(lambda: cc.merge_pull_request_by_three_way(
        pullRequestId=pr_id, repositoryName=repo))
    assert code == "PullRequestAlreadyClosedException", (
        f"merging a CLOSED pull request raised {code!r}, expected "
        f"'PullRequestAlreadyClosedException'"
    )
    assert message == (
        "The specified pull request is marked as Closed. A closed pull request cannot be merged."
    ), message

    # Effect absent: the destination ref did not move and the feature file is not there.
    after = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert after == main_tip, (
        f"main is at {after!r} after the refused merge, expected the pre-merge tip "
        f"{main_tip!r}"
    )
    try:
        cc.get_file(repositoryName=repo, commitSpecifier=main_tip, filePath="feature.txt")
        raise AssertionError(
            f"feature.txt resolves on main at {main_tip} even though the merge was refused"
        )
    except ClientError as exc:
        absent = exc.response.get("Error", {}).get("Code")
        assert absent == "FileDoesNotExistException", (
            f"GetFile for the unmerged path raised {absent!r} at main's tip"
        )
        absent_message = exc.response["Error"].get("Message")
        assert absent_message == "Could not find path feature.txt", absent_message
    # The pull request itself did not quietly flip back to a merged state.
    still = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert still["pullRequestStatus"] == "CLOSED", (
        f"after the refused merge the pull request reports "
        f"{still['pullRequestStatus']!r}, expected it to stay 'CLOSED'"
    )
    assert still["pullRequestTargets"][0].get("mergeMetadata", {}).get("isMerged") is False, (
        f"the refused pull request reports mergeMetadata "
        f"{still['pullRequestTargets'][0].get('mergeMetadata')!r}; isMerged must stay False"
    )

    # Positive control, in this file: an OPEN pull request over the identical source and
    # destination references merges and advances main. Real AWS permits a second pull
    # request for the same branch pair while the first is CLOSED.
    control = cc.create_pull_request(title="control", targets=targets)["pullRequest"]
    control_id = control["pullRequestId"]
    assert control_id != pr_id, "the control pull request reused the closed one's id"
    merged = cc.merge_pull_request_by_three_way(pullRequestId=control_id,
                                               repositoryName=repo)["pullRequest"]
    metadata = merged["pullRequestTargets"][0]["mergeMetadata"]
    assert metadata["isMerged"] is True, (
        f"the control pull request's mergeMetadata is {metadata!r}, expected isMerged True"
    )
    merge_commit = metadata["mergeCommitId"]
    advanced = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert advanced == merge_commit, (
        f"main is at {advanced!r} after the control merge, expected the merge commit "
        f"{merge_commit!r}"
    )
    landed = cc.get_file(repositoryName=repo, commitSpecifier=merge_commit,
                         filePath="feature.txt")
    assert landed["fileContent"] == feature_body, (
        f"after the control merge feature.txt on main is {landed['fileContent']!r}, "
        f"expected {feature_body!r} -- the same change the closed request carried"
    )
    parents = cc.get_commit(repositoryName=repo, commitId=merge_commit)["commit"]["parents"]
    assert sorted(parents) == sorted([main_tip, feature_tip]), (
        f"the control merge commit's parents are {parents!r}, expected the two tips "
        f"{[main_tip, feature_tip]!r}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because
    a target that accepts a call real AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
