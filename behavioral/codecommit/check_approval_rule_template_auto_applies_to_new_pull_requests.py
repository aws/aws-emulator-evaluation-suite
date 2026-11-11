"""approval-rule-template-auto-applies-to-new-pull-requests."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "approval-rule-template-auto-applies-to-new-pull-requests"
GROUP = "server-side"
SERVICES = ["codecommit"]

_TEMPLATE_CONTENT = (
    '{"Version":"2018-11-08","Statements":'
    '[{"Type":"Approvers","NumberOfApprovalsNeeded":1}]}'
)


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a template is associated with a repository, every pull request
    subsequently opened on that repository is server-side auto-stamped with an
    approval rule derived from the template."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-autorule-repo-")
    template_name = ctx.unique_name("sim2real-autorule-tmpl-")

    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "autorule"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    template = cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=_TEMPLATE_CONTENT,
        approvalRuleTemplateDescription="auto-apply check",
    )["approvalRuleTemplate"]
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    # Associate BEFORE any pull request exists on the repo.
    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    ctx.on_cleanup(
        lambda: cc.disassociate_approval_rule_template_from_repository(
            approvalRuleTemplateName=template_name, repositoryName=repo_name
        )
    )

    main_head = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"root\n",
        filePath="root.txt",
        commitMessage="initial commit",
        name="sim2real",
        email="sim2real@example.com",
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=main_head)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"change\n",
        filePath="change.txt",
        parentCommitId=main_head,
        commitMessage="feature change",
        name="sim2real",
        email="sim2real@example.com",
    )

    pr = cc.create_pull_request(
        title="Feature PR",
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

    # The PR object itself must carry an approval rule whose origin is the template
    # we associated -- created server-side, without any CreatePullRequestApprovalRule
    # call from us.
    fetched_pr = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    generated_rules = fetched_pr.get("approvalRules", [])
    origin_names = {
        r.get("originApprovalRuleTemplate", {}).get("approvalRuleTemplateName")
        for r in generated_rules
    }
    assert template_name in origin_names, (
        f"expected an auto-generated approval rule from template {template_name!r}, "
        f"got rules with origins {origin_names!r}"
    )

    # The materialized rule must be a copy of what the service itself stored for the
    # template, not a re-rendering of the JSON literal this check sent.
    materialized = next(
        r
        for r in generated_rules
        if r.get("originApprovalRuleTemplate", {}).get("approvalRuleTemplateName") == template_name
    )
    assert materialized["approvalRuleContent"] == template["approvalRuleTemplateContent"], (
        f"materialized rule content {materialized['approvalRuleContent']!r} does not match "
        f"the template's own stored content {template['approvalRuleTemplateContent']!r}"
    )
    assert materialized["ruleContentSha256"] == template["ruleContentSha256"], (
        f"materialized rule sha256 {materialized['ruleContentSha256']!r} does not match "
        f"the template's {template['ruleContentSha256']!r}"
    )

    evaluation = cc.evaluate_pull_request_approval_rules(
        pullRequestId=pr_id, revisionId=revision_id
    )["evaluation"]
    assert evaluation["approved"] is False, (
        f"expected the PR to be unapproved with an unsatisfied template rule outstanding, "
        f"got evaluation {evaluation!r}"
    )
    rule_name = materialized["approvalRuleName"]
    assert rule_name in evaluation["approvalRulesNotSatisfied"], (
        f"the auto-generated rule {rule_name!r} should show up as not-yet-satisfied, "
        f"got not-satisfied={evaluation['approvalRulesNotSatisfied']!r}"
    )
    assert rule_name not in evaluation["approvalRulesSatisfied"], (
        f"the auto-generated rule {rule_name!r} should not show up as satisfied, "
        f"got satisfied={evaluation['approvalRulesSatisfied']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
