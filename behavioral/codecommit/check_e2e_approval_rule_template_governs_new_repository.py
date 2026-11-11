"""e2e-approval-rule-template-governs-new-repository."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "e2e-approval-rule-template-governs-new-repository"
GROUP = "e2e"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A template associated before a PR is opened materializes as an approval rule on the PR,
    unsatisfied in EvaluatePullRequestApprovalRules until approved; that rule cannot be deleted
    directly, while a rule created on the PR can."""
    cc = ctx.client("codecommit")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    template_name = ctx.unique_name("sim2real-cc-tmpl-")
    rule_content = {
        "Version": "2018-11-08",
        "Statements": [
            {
                "Type": "Approvers",
                "NumberOfApprovalsNeeded": 1,
                "ApprovalPoolMembers": [f"CodeCommitApprovers:{account_id}:*"],
            }
        ],
    }
    template = cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=json.dumps(rule_content),
        approvalRuleTemplateDescription="sim2real behavioral check template",
    )["approvalRuleTemplate"]
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "e2e-approval-rule-template"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    ctx.on_cleanup(
        lambda: cc.disassociate_approval_rule_template_from_repository(
            approvalRuleTemplateName=template_name, repositoryName=repo_name
        )
    )

    associated = cc.list_associated_approval_rule_templates_for_repository(repositoryName=repo_name)[
        "approvalRuleTemplateNames"
    ]
    assert template_name in associated

    initial_commit_id = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"hello world\n",
        filePath="README.md",
        commitMessage="initial commit",
    )["commitId"]
    cc.update_default_branch(repositoryName=repo_name, defaultBranchName="main")
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=initial_commit_id)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"feature contents\n",
        filePath="feature.txt",
        commitMessage="feature commit",
        parentCommitId=initial_commit_id,
    )

    pr = cc.create_pull_request(
        title="pr under template governance",
        description="sim2real behavioral check PR",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]
    revision_id = pr["revisionId"]

    # The template must have materialized into a real approval rule on the PR already.
    # Read it back independently rather than trusting CreatePullRequest's own response,
    # since that is where an implementation that only echoes its input would show up.
    fetched_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    approval_rules = fetched_pr["approvalRules"]
    assert len(approval_rules) == 1, (
        f"expected exactly one materialized approval rule on the PR, got {approval_rules!r}"
    )
    materialized_rule = approval_rules[0]
    origin = materialized_rule.get("originApprovalRuleTemplate")
    assert origin is not None and origin.get("approvalRuleTemplateName") == template_name, (
        f"materialized rule {materialized_rule!r} does not carry originApprovalRuleTemplate "
        f"for {template_name!r}"
    )
    # The materialized content must be a copy of what the service itself stored for the
    # template, not a re-rendering of the JSON this check happened to send.
    assert materialized_rule["approvalRuleContent"] == template["approvalRuleTemplateContent"], (
        f"materialized rule content {materialized_rule['approvalRuleContent']!r} does not match "
        f"the template's own stored content {template['approvalRuleTemplateContent']!r}"
    )
    assert materialized_rule["ruleContentSha256"] == template["ruleContentSha256"], (
        f"materialized rule sha256 {materialized_rule['ruleContentSha256']!r} does not match "
        f"the template's {template['ruleContentSha256']!r}"
    )

    evaluation = cc.evaluate_pull_request_approval_rules(pullRequestId=pr_id, revisionId=revision_id)[
        "evaluation"
    ]
    assert evaluation["approved"] is False
    assert materialized_rule["approvalRuleName"] in evaluation["approvalRulesNotSatisfied"]
    assert materialized_rule["approvalRuleName"] not in evaluation["approvalRulesSatisfied"]

    # Deleting a template-derived rule directly on the PR is not permitted; only the
    # template mechanism may remove it.
    from botocore.exceptions import ClientError

    try:
        cc.delete_pull_request_approval_rule(
            pullRequestId=pr_id, approvalRuleName=materialized_rule["approvalRuleName"]
        )
        raise AssertionError("expected CannotDeleteApprovalRuleFromTemplateException")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "CannotDeleteApprovalRuleFromTemplateException"
        expected = (
            "The approval rule cannot be deleted from the pull request because it was created "
            "by an approval rule template and automatically applied to the pull request."
        )
        message = exc.response["Error"].get("Message")
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read shows the template-derived rule is still attached
    # after the rejected delete.
    still_there = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    assert any(r["approvalRuleName"] == materialized_rule["approvalRuleName"] for r in still_there), (
        f"template-derived rule {materialized_rule['approvalRuleName']!r} disappeared from the "
        f"PR after a delete that should have been rejected: {still_there!r}"
    )

    # Positive control: a rule created directly on the pull request (not template-derived)
    # deletes normally, so the rejection above is specific to template origin rather than a
    # blanket refusal to delete any approval rule on this PR.
    direct_rule_name = ctx.unique_name("sim2real-cc-direct-rule-")
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id,
        approvalRuleName=direct_rule_name,
        approvalRuleContent=json.dumps(rule_content),
    )
    cc.delete_pull_request_approval_rule(pullRequestId=pr_id, approvalRuleName=direct_rule_name)
    after_direct_delete = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]["approvalRules"]
    assert not any(r["approvalRuleName"] == direct_rule_name for r in after_direct_delete), (
        f"directly-created rule {direct_rule_name!r} should delete cleanly, "
        f"still present in {after_direct_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
