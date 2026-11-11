"""merge-pull-request-refused-when-approval-rules-not-satisfied."""
from __future__ import annotations

import hashlib
import json
import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-pull-request-refused-when-approval-rules-not-satisfied"
GROUP = 'overly-permissive'
SERVICES = ['codecommit']


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unsatisfiable approval rule refuses MergePullRequest (PullRequestApprovalRulesNotSatisfied)
    with the branch untouched and the PR open; after an override the same merge succeeds, while
    evaluation still reports approved=false and only `overridden` flips.
    """
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccmerge"},
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    base_txt = b"the released version\n"
    feat_txt = b"the proposed change\n"

    c_base = cc.put_file(
        repositoryName=repo, branchName="main", filePath="file.txt",
        fileContent=base_txt, commitMessage="base",
    )["commitId"]
    feature = ctx.unique_name("sim2real-behav-branch-")
    cc.create_branch(repositoryName=repo, branchName=feature, commitId=c_base)
    c_feat = cc.put_file(
        repositoryName=repo, branchName=feature, filePath="file.txt",
        fileContent=feat_txt, parentCommitId=c_base, commitMessage="proposed change",
    )["commitId"]

    created = cc.create_pull_request(
        title="sim2real approval-rule gate",
        description="merge must be blocked until the approval rule is satisfied or overridden",
        targets=[{
            "repositoryName": repo,
            "sourceReference": feature,
            "destinationReference": "main",
        }],
        clientRequestToken=ctx.unique_name("sim2real-behav-token-"),
    )["pullRequest"]
    pr_id = created["pullRequestId"]
    assert created["pullRequestStatus"] == "OPEN", f"new pull request status {created['pullRequestStatus']!r}"
    assert len(created["pullRequestTargets"]) == 1, f"pullRequestTargets {created['pullRequestTargets']!r}"
    target = created["pullRequestTargets"][0]
    assert target["repositoryName"] == repo, f"target repositoryName {target['repositoryName']!r}"
    assert target["sourceCommit"] == c_feat, f"target sourceCommit {target['sourceCommit']!r} != {c_feat!r}"
    assert target["destinationCommit"] == c_base, f"target destinationCommit {target['destinationCommit']!r}"
    assert target["mergeBase"] == c_base, f"target mergeBase {target['mergeBase']!r} != {c_base!r}"

    # Positive control for title mutation, established while the PR is still OPEN and
    # unencumbered -- needed later to tell "closed state blocks retitling" apart from
    # "retitling is unimplemented" once the same call is expected to fail post-merge.
    retitled_open = cc.update_pull_request_title(
        pullRequestId=pr_id, title="sim2real approval-rule gate (retitled while open)",
    )["pullRequest"]
    assert retitled_open["title"] == "sim2real approval-rule gate (retitled while open)", (
        f"update_pull_request_title on an OPEN pull request did not take effect: {retitled_open['title']!r}"
    )
    assert cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["title"] == (
        "sim2real approval-rule gate (retitled while open)"
    ), "the title update on an OPEN pull request is not visible on an independent read"

    # The approval pool names a principal in this account that does not exist (pools are
    # matched by ARN, not resolved), so the rule can never be satisfied by anyone. Partition and account are read off the
    # repository ARN -- no STS call, no credential read.
    arn_parts = meta["Arn"].split(":")
    assert len(arn_parts) >= 5 and arn_parts[0] == "arn", f"unexpected repository ARN {meta['Arn']!r}"
    partition, account = arn_parts[1], arn_parts[4]
    pool_arn = f"arn:{partition}:iam::{account}:user/sim2real-behav-no-such-approver"

    rule_name = "sim2real-behav-require-one-approval"
    rule_content = json.dumps({
        "Version": "2018-11-08",
        "Statements": [{
            "Type": "Approvers",
            "NumberOfApprovalsNeeded": 1,
            "ApprovalPoolMembers": [pool_arn],
        }],
    })
    rule = cc.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName=rule_name, approvalRuleContent=rule_content,
    )["approvalRule"]
    assert rule["approvalRuleName"] == rule_name, f"approvalRuleName {rule['approvalRuleName']!r}"
    # AWS does not echo the submitted bytes: it re-serialises the rule document canonically with
    # all inter-token whitespace removed. So the round-trip is asserted at both levels: the
    # document is semantically identical, and its serialisation is exactly the compact form.
    returned_content = rule["approvalRuleContent"]
    assert json.loads(returned_content) == json.loads(rule_content), (
        f"the approval rule document did not round-trip: {returned_content!r}"
    )
    assert returned_content == json.dumps(
        json.loads(rule_content), separators=(",", ":")
    ), (
        f"approvalRuleContent must come back canonicalised with no inter-token whitespace, got "
        f"{returned_content!r}"
    )
    assert "originApprovalRuleTemplate" not in rule or not rule["originApprovalRuleTemplate"], (
        f"a directly created rule claims a template origin: {rule.get('originApprovalRuleTemplate')!r}"
    )
    sha = rule["ruleContentSha256"]
    assert len(sha) == 64 and all(c in string.hexdigits for c in sha), (
        f"ruleContentSha256 {sha!r} is not a 64-character hex digest"
    )
    # And the digest is over the CANONICALISED content, not over what the caller sent -- which is
    # the only way a caller can recompute it, and the fact an emulator that hashes the request
    # body would get wrong while still returning a plausible 64-hex string.
    assert sha == hashlib.sha256(returned_content.encode("utf-8")).hexdigest(), (
        f"ruleContentSha256 must be the sha256 of the canonicalised approvalRuleContent; got "
        f"{sha!r} for {returned_content!r}"
    )
    assert sha != hashlib.sha256(rule_content.encode("utf-8")).hexdigest(), (
        "the submitted spacing must not be what is digested -- this check's rule_content is "
        "deliberately spaced so the two digests differ"
    )

    # The rule is attached to the pull request as read back, not just to the create call.
    on_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    assert [r["approvalRuleName"] for r in on_pr["approvalRules"]] == [rule_name], (
        f"GetPullRequest lists approval rules {[r['approvalRuleName'] for r in on_pr['approvalRules']]!r}"
    )

    ev = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id),
    )["evaluation"]
    assert ev["approved"] is False, f"evaluation reports approved={ev['approved']!r} with nobody having approved"
    assert ev["overridden"] is False, f"evaluation reports overridden={ev['overridden']!r} before any override"
    assert ev["approvalRulesNotSatisfied"] == [rule_name], (
        f"approvalRulesNotSatisfied {ev['approvalRulesNotSatisfied']!r}, expected [{rule_name!r}]"
    )
    assert ev.get("approvalRulesSatisfied", []) == [], (
        f"approvalRulesSatisfied {ev.get('approvalRulesSatisfied')!r}, expected none"
    )

    # Positive control for REVOKE, established before the PR is ever overridden for real --
    # needed later to tell "closed state blocks revoking an override" apart from "REVOKE is
    # unimplemented" once the same call is expected to fail post-merge.
    cc.override_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id), overrideStatus="OVERRIDE",
    )
    probe_state = cc.get_pull_request_override_state(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id),
    )
    assert probe_state["overridden"] is True, f"OVERRIDE probe did not take effect: {probe_state!r}"
    cc.override_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id), overrideStatus="REVOKE",
    )
    probe_state2 = cc.get_pull_request_override_state(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id),
    )
    assert probe_state2["overridden"] is False, f"REVOKE probe did not take effect: {probe_state2!r}"

    try:
        cc.merge_pull_request_by_fast_forward(pullRequestId=pr_id, repositoryName=repo)
        raise AssertionError(
            "the pull request merged while its approval rule was unsatisfied -- approval "
            "rules are being stored but not evaluated"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "PullRequestApprovalRulesNotSatisfiedException", (
            f"merging an unapproved pull request raised {code!r}, "
            "expected PullRequestApprovalRulesNotSatisfiedException"
        )
        message = exc.response["Error"].get("Message")
        assert message == (
            "You cannot merge the pull request because the requirements for one or more "
            "approval rules have not been met. For details about the approval rules that "
            "still have requirements, use EvaluatePullRequestApprovalRules."
        ), message

    # Effect absent: destination unmoved, content unchanged, pull request still open.
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == c_base, (
        "the refused merge advanced the destination branch"
    )
    assert cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="file.txt"
    )["fileContent"] == base_txt, "the refused merge changed the destination content"
    assert cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["pullRequestStatus"] == "OPEN", (
        "the refused merge closed the pull request"
    )

    # Control: override the rule, then the identical merge call succeeds.
    cc.override_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id), overrideStatus="OVERRIDE",
    )
    state = cc.get_pull_request_override_state(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id),
    )
    assert state["overridden"] is True, f"GetPullRequestOverrideState overridden={state['overridden']!r}"
    assert state.get("overrider"), "an overridden pull request reports no overrider ARN"

    # An override does NOT satisfy the rule: only `overridden` flips; `approved` stays false and
    # the rule stays in approvalRulesNotSatisfied, so the merge gate is (approved OR overridden).
    # The record still says the rule was never met, and by whom it was bypassed.
    ev2 = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id),
    )["evaluation"]
    assert ev2["overridden"] is True, f"after OVERRIDE, evaluation overridden={ev2['overridden']!r}"
    assert ev2["approved"] is False, (
        f"an override must not be reported as approval: after OVERRIDE the evaluation still "
        f"reports approved=false, got approved={ev2['approved']!r}"
    )
    assert ev2["approvalRulesNotSatisfied"] == [rule_name], (
        f"the overridden rule must still be reported as unsatisfied, got "
        f"{ev2['approvalRulesNotSatisfied']!r}"
    )
    assert ev2.get("approvalRulesSatisfied", []) == [], (
        f"an override satisfies nothing, got approvalRulesSatisfied="
        f"{ev2.get('approvalRulesSatisfied')!r}"
    )

    merged = cc.merge_pull_request_by_fast_forward(
        pullRequestId=pr_id, repositoryName=repo,
    )["pullRequest"]
    # PullRequestStatusEnum has no MERGED member: a merged pull request is CLOSED with
    # mergeMetadata.isMerged true. An emulator that invents a MERGED status is wrong.
    assert merged["pullRequestStatus"] == "CLOSED", (
        f"merged pull request status {merged['pullRequestStatus']!r}, expected CLOSED"
    )
    merged_meta = merged["pullRequestTargets"][0]["mergeMetadata"]
    assert merged_meta["isMerged"] is True, f"mergeMetadata {merged_meta!r} does not report the merge"
    assert merged_meta["mergeOption"] == "FAST_FORWARD_MERGE", (
        f"mergeMetadata mergeOption {merged_meta.get('mergeOption')!r}, expected FAST_FORWARD_MERGE"
    )
    assert merged_meta.get("mergedBy"), f"mergeMetadata reports no mergedBy: {merged_meta!r}"
    # A fast-forward creates no merge commit: the recorded mergeCommitId IS the source tip.
    assert merged_meta["mergeCommitId"] == c_feat, (
        f"a fast-forward merge records the source commit as its mergeCommitId, got "
        f"{merged_meta.get('mergeCommitId')!r} for source {c_feat!r}"
    )
    tip = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert tip == c_feat, f"after a fast-forward merge main is {tip!r}, expected the source commit {c_feat!r}"
    assert cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="file.txt"
    )["fileContent"] == feat_txt, "the accepted merge did not bring the proposed content onto main"

    # The evaluation survives the merge unchanged: still overridden, still not approved, and the
    # rule still named as unsatisfied. The bypass is a permanent part of the pull request's record
    # rather than something the merge reconciles away.
    ev3 = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id),
    )["evaluation"]
    assert (ev3["overridden"], ev3["approved"]) == (True, False), (
        f"after the merge the evaluation must still read overridden/not-approved, got {ev3!r}"
    )
    assert ev3["approvalRulesNotSatisfied"] == [rule_name], (
        f"the merged pull request must still record the rule as unsatisfied, got {ev3!r}"
    )

    # Re-merging an already-merged pull request is IDEMPOTENT, not an error:
    # MergePullRequestByFastForward returns 200 with the SAME mergeMetadata, including the same
    # mergeCommitId, and does not merge anything a second time.
    remerged = cc.merge_pull_request_by_fast_forward(
        pullRequestId=pr_id, repositoryName=repo,
    )["pullRequest"]
    assert remerged["pullRequestStatus"] == "CLOSED", (
        f"the re-merge must leave the pull request CLOSED, got {remerged['pullRequestStatus']!r}"
    )
    remerged_meta = remerged["pullRequestTargets"][0]["mergeMetadata"]
    assert remerged_meta["isMerged"] is True, remerged_meta
    assert remerged_meta["mergeCommitId"] == merged_meta["mergeCommitId"], (
        f"the re-merge must report the ORIGINAL merge, not a new one: mergeCommitId "
        f"{remerged_meta.get('mergeCommitId')!r} != {merged_meta['mergeCommitId']!r}"
    )
    assert remerged_meta["mergedBy"] == merged_meta["mergedBy"], (remerged_meta, merged_meta)
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == c_feat, (
        "the idempotent re-merge must not have advanced the destination branch again"
    )

    # What the closed state DOES gate: the pull request's own fields can no longer be mutated.
    try:
        cc.update_pull_request_title(pullRequestId=pr_id, title="sim2real closed-pr retitle")
        raise AssertionError("a merged pull request's title was updated")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "PullRequestAlreadyClosedException", (
            f"retitling a closed pull request raised {code!r}, expected "
            "PullRequestAlreadyClosedException"
        )
        message = exc.response["Error"].get("Message")
        assert message == (
            "The change cannot be made because the state of the pull request is CLOSED. You "
            "cannot update the title or description of a pull request after it has been closed."
        ), message
    assert cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["title"] == (
        "sim2real approval-rule gate (retitled while open)"
    ), "the refused retitle changed the pull request's title"

    # And its override cannot be revoked after the fact -- same code, so the closed state gates the
    # approval-rule decision surface too, even though the merge call itself is idempotent.
    try:
        cc.override_pull_request_approval_rules(
            pullRequestId=pr_id, revisionId=_revision(cc, pr_id), overrideStatus="REVOKE",
        )
        raise AssertionError("the override of a merged pull request was revoked")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "PullRequestAlreadyClosedException", (
            f"revoking the override on a closed pull request raised {code!r}, expected "
            "PullRequestAlreadyClosedException"
        )
        message = exc.response["Error"].get("Message")
        assert message == (
            "This pull request is already merged or closed. You cannot override the approval "
            "status of a merged or closed pull request. Modify your request, and then try again."
        ), message
    final_state = cc.get_pull_request_override_state(
        pullRequestId=pr_id, revisionId=_revision(cc, pr_id),
    )
    assert final_state["overridden"] is True, (
        f"the refused revoke changed the override state: {final_state!r}"
    )



def _revision(cc, pr_id):
    """The pull request's current revisionId, read fresh before each revision-scoped call:
    a stale revision is rejected with RevisionNotCurrentException."""
    pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    rev = pr["revisionId"]
    assert rev, f"pull request {pr_id} reported no revisionId"
    return rev


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
