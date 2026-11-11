"""approval-rule-template-auto-attaches-to-new-pull-requests."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "approval-rule-template-auto-attaches-to-new-pull-requests"
GROUP = 'lifecycle'
SERVICES = ['codecommit']


@tags("axis:happy-path", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """An associated template attaches a copy of itself, with originApprovalRuleTemplate, to pull
    requests opened after the association; it is not retroactive, stops after disassociation, and
    disassociation does not strip an already-attached rule.
    """
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-cctpl-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "cctpl"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    base = cc.put_file(repositoryName=repo, branchName="main", filePath="base.txt",
                       fileContent=b"base\n", commitMessage="base")["commitId"]
    for branch in ("before", "after", "disassociated"):
        cc.create_branch(repositoryName=repo, branchName=branch, commitId=base)
        cc.put_file(repositoryName=repo, branchName=branch, filePath=f"{branch}.txt",
                    fileContent=f"work on {branch}\n".encode("ascii"),
                    parentCommitId=base, commitMessage=f"work on {branch}")

    def _open(source):
        return cc.create_pull_request(
            title=f"from {source}",
            targets=[{"repositoryName": repo, "sourceReference": source,
                      "destinationReference": "main"}])["pullRequest"]

    early = _open("before")
    assert early["approvalRules"] == [], (
        f"a pull request opened before any template association already carries "
        f"{early['approvalRules']!r}"
    )

    # Templates are account-and-region scoped, so the name must be unique per run.
    template_name = ctx.unique_name("sim2real-behav-cctpl-t-")
    supplied = ('{"Version": "2018-11-08", "DestinationReferences": ["refs/heads/main"], '
                '"Statements": [{"Type": "Approvers", "NumberOfApprovalsNeeded": 1}]}')
    template = cc.create_approval_rule_template(
        approvalRuleTemplateName=template_name,
        approvalRuleTemplateContent=supplied)["approvalRuleTemplate"]
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(
        approvalRuleTemplateName=template_name))
    cc.associate_approval_rule_template_with_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo)
    ctx.on_cleanup(lambda: _swallow(
        lambda: cc.disassociate_approval_rule_template_from_repository(
            approvalRuleTemplateName=template_name, repositoryName=repo)))

    # Wait until the association is listed, so an absent rule below is not propagation lag.
    associated = _poll_membership(
        lambda: _all_repositories_for_template(cc, template_name), repo, want=True,
        timeout_s=120.0)
    assert associated, (
        f"{repo!r} never appeared in ListRepositoriesForApprovalRuleTemplate for "
        f"{template_name!r}; the association did not take effect"
    )

    late = _open("after")
    rules = late["approvalRules"]
    assert len(rules) == 1, (
        f"a pull request opened after the association carries {len(rules)} approval rules "
        f"{rules!r}, expected exactly one"
    )
    origin = rules[0].get("originApprovalRuleTemplate")
    assert origin is not None, (
        f"the attached rule {rules[0]!r} carries no originApprovalRuleTemplate, so nothing "
        f"records that it came from a template rather than from the caller"
    )
    assert origin["approvalRuleTemplateName"] == template_name, (
        f"the attached rule names template {origin['approvalRuleTemplateName']!r}, expected "
        f"{template_name!r}"
    )
    assert origin["approvalRuleTemplateId"] == template["approvalRuleTemplateId"], (
        f"the attached rule names template id {origin['approvalRuleTemplateId']!r}, expected "
        f"{template['approvalRuleTemplateId']!r}"
    )
    assert rules[0]["approvalRuleName"] == template_name, (
        f"the attached rule is named {rules[0]['approvalRuleName']!r}, expected the "
        f"template's own name {template_name!r}"
    )
    # Compare against the stored template content: AWS strips whitespace from the JSON on create.
    assert rules[0]["approvalRuleContent"] == template["approvalRuleTemplateContent"], (
        f"the attached rule's content is {rules[0]['approvalRuleContent']!r}; the template "
        f"holds {template['approvalRuleTemplateContent']!r} -- the rule must be a copy of "
        f"the template, not a re-rendering"
    )
    assert rules[0]["ruleContentSha256"] == template["ruleContentSha256"], (
        f"the attached rule's ruleContentSha256 is {rules[0]['ruleContentSha256']!r}, the "
        f"template's is {template['ruleContentSha256']!r}"
    )
    assert rules[0]["lastModifiedUser"] == "codecommit.amazonaws.com", (
        f"the attached rule's lastModifiedUser is {rules[0]['lastModifiedUser']!r}; a "
        f"template-applied rule is written by the service, not by the caller"
    )

    # Re-read the earlier pull request: association must not apply retroactively.
    still_early = cc.get_pull_request(pullRequestId=early["pullRequestId"])["pullRequest"]
    assert still_early["approvalRules"] == [], (
        f"the pull request opened before the association now carries "
        f"{still_early['approvalRules']!r}; associating a template must not reach backwards"
    )

    cc.disassociate_approval_rule_template_from_repository(
        approvalRuleTemplateName=template_name, repositoryName=repo)
    gone = _poll_membership(
        lambda: _all_repositories_for_template(cc, template_name), repo, want=False,
        timeout_s=120.0)
    assert gone, (
        f"{repo!r} is still listed for {template_name!r} after disassociation"
    )
    third = _open("disassociated")
    assert third["approvalRules"] == [], (
        f"a pull request opened after disassociation carries {third['approvalRules']!r}, "
        f"expected none"
    )
    # Disassociation does not retract a rule already attached to a pull request.
    kept = cc.get_pull_request(pullRequestId=late["pullRequestId"])["pullRequest"]
    assert len(kept["approvalRules"]) == 1, (
        f"the pull request that had the templated rule now carries "
        f"{kept['approvalRules']!r}; disassociation must not strip an applied rule"
    )
    assert kept["approvalRules"][0]["approvalRuleId"] == rules[0]["approvalRuleId"], (
        f"the surviving rule's id is {kept['approvalRules'][0]['approvalRuleId']!r}, "
        f"expected {rules[0]['approvalRuleId']!r}"
    )


def _swallow(fn):
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ApprovalRuleTemplateDoesNotExistException",
            "EncryptionKeyNotFoundException",
            "RepositoryDoesNotExistException",
        ):
            raise


def _all_repositories_for_template(cc, name):
    """Every repository associated with a template, across all pages.

    ListRepositoriesForApprovalRuleTemplate has no botocore paginator, so nextToken is looped.
    """
    names, token = [], None
    while True:
        kwargs = {"approvalRuleTemplateName": name}
        if token:
            kwargs["nextToken"] = token
        page = cc.list_repositories_for_approval_rule_template(**kwargs)
        names += page.get("repositoryNames", [])
        token = page.get("nextToken")
        if not token:
            return names


def _poll_membership(list_fn, member, *, want: bool, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if (member in list_fn()) is want:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
