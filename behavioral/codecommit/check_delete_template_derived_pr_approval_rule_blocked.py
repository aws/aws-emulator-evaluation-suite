"""delete-template-derived-pr-approval-rule-blocked."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-template-derived-pr-approval-rule-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePullRequestApprovalRule on a rule from an associated approval rule template raises
    CannotDeleteApprovalRuleFromTemplateException and the rule stays attached, while deleting
    a custom (non-template) rule on the same pull request succeeds."""
    cc = ctx.client("codecommit")

    template_name = ctx.unique_name("sim2real-behav-arttpl-")
    template_content = json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [
                {
                    "Type": "Approvers",
                    "NumberOfApprovalsNeeded": 1,
                }
            ],
        }
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name, approvalRuleTemplateContent=template_content
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=template_name))

    repo_name = ctx.unique_name("sim2real-behav-arttplrepo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "arttplrepo"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo_name
    )
    ctx.on_cleanup(
        lambda: cc.disassociate_approval_rule_template_from_repository(
            approvalRuleTemplateName=template_name, repositoryName=repo_name
        )
    )

    put = cc.put_file(
        repositoryName=repo_name, branchName="main", filePath="a.txt", fileContent=b"x"
    )
    main_tip = put["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=main_tip)
    cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        filePath="b.txt",
        fileContent=b"y",
        parentCommitId=main_tip,
    )

    pr = cc.create_pull_request(
        title="PR with template rule",
        targets=[
            {
                "repositoryName": repo_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )
    pr_id = pr["pullRequest"]["pullRequestId"]

    pull_request = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    template_rules = [
        rule
        for rule in pull_request.get("approvalRules", [])
        if rule.get("originApprovalRuleTemplate", {}).get("approvalRuleTemplateName")
        == template_name
    ]
    assert len(template_rules) == 1, "expected exactly one rule generated from the associated template"
    template_rule_name = template_rules[0]["approvalRuleName"]

    code, message = _error(
        lambda: cc.delete_pull_request_approval_rule(
            pullRequestId=pr_id, approvalRuleName=template_rule_name
        )
    )
    assert code == "CannotDeleteApprovalRuleFromTemplateException", (
        f"expected CannotDeleteApprovalRuleFromTemplateException, got {code!r}"
    )
    expected = (
        "The approval rule cannot be deleted from the pull request because it was created by an "
        "approval rule template and automatically applied to the pull request."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the template-derived rule is still attached to the pull request
    after = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    after_rule_names = [r["approvalRuleName"] for r in after.get("approvalRules", [])]
    assert template_rule_name in after_rule_names, (
        f"expected template-derived rule {template_rule_name!r} to remain attached, "
        f"but pull request approval rules are now {after_rule_names!r}"
    )

    # positive control: a custom (non-template) rule on the same PR can be deleted
    custom_rule_name = ctx.unique_name("custom-rule-")
    custom_content = json.dumps(
        {
            "Version": "2018-11-08",
            "Statements": [
                {
                    "Type": "Approvers",
                    "NumberOfApprovalsNeeded": 1,
                }
            ],
        }
    )
    cc.create_pull_request_approval_rule(
        pullRequestId=pr_id, approvalRuleName=custom_rule_name, approvalRuleContent=custom_content
    )
    cc.delete_pull_request_approval_rule(pullRequestId=pr_id, approvalRuleName=custom_rule_name)
    final = cc.get_pull_request(pullRequestId=pr_id)["pullRequest"]
    final_rule_names = [r["approvalRuleName"] for r in final.get("approvalRules", [])]
    assert custom_rule_name not in final_rule_names, (
        f"expected custom rule {custom_rule_name!r} to be gone after delete, "
        f"but pull request approval rules are still {final_rule_names!r}"
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
