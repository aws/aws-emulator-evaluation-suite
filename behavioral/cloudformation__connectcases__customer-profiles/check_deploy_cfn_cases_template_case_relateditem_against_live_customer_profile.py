"""deploy-cfn-cases-template-case-relateditem-against-live-customer-profile."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-cases-template-case-relateditem-against-live-customer-profile"
GROUP = "deploy"
SERVICES = ["cloudformation", "connectcases", "customer-profiles"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the templates, then run(). ----

_CASES_NOT_FOUND = ("ResourceNotFoundException", "Requested resource not found.")
_RELATED_CASE_NOT_FOUND = ("ResourceNotFoundException", "A case with the specified ID was not found.")

#: A Cases domain plus the Customer Profiles domain that mints the ARN AWS::Cases::Case needs.
_TEMPLATE_A = """
AWSTemplateFormatVersion: '2010-09-09'
Description: A Cases domain and a Customer Profiles domain.
Parameters:
  CasesDomainName: {Type: String}
  ProfilesDomainName: {Type: String}
Resources:
  CasesDomain:
    Type: AWS::Cases::Domain
    Properties:
      Name: !Ref CasesDomainName
  ProfilesDomain:
    Type: AWS::CustomerProfiles::Domain
    Properties:
      DomainName: !Ref ProfilesDomainName
      DefaultExpirationDays: 30
Outputs:
  CasesDomainId: {Value: !GetAtt CasesDomain.DomainId}
  CasesDomainRef: {Value: !Ref CasesDomain}
  CasesDomainArn: {Value: !GetAtt CasesDomain.DomainArn}
  ProfilesDomainRef: {Value: !Ref ProfilesDomain}
"""

#: A template and a case created from it, with a related comment, in the domain from stack A.
_TEMPLATE_B = """
AWSTemplateFormatVersion: '2010-09-09'
Description: A Cases template, a case created from it, and a related comment on the case.
Parameters:
  CasesDomainId: {Type: String}
  TemplateName: {Type: String}
  CaseTitle: {Type: String}
  CustomerArn: {Type: String}
  CommentBody: {Type: String}
Resources:
  Template:
    Type: AWS::Cases::Template
    Properties:
      DomainId: !Ref CasesDomainId
      Name: !Ref TemplateName
      Status: Active
  Case:
    Type: AWS::Cases::Case
    Properties:
      DomainId: !Ref CasesDomainId
      TemplateId: !GetAtt Template.TemplateId
      Title: !Ref CaseTitle
      CustomerId: !Ref CustomerArn
  RelatedItem:
    Type: AWS::Cases::RelatedItem
    Properties:
      DomainId: !Ref CasesDomainId
      CaseId: !GetAtt Case.CaseId
      Type: Comment
      Content:
        Comment:
          Body: !Ref CommentBody
          ContentType: Text/Plain
Outputs:
  TemplateId: {Value: !GetAtt Template.TemplateId}
  TemplateRef: {Value: !Ref Template}
  CaseId: {Value: !GetAtt Case.CaseId}
  CaseRef: {Value: !Ref Case}
  RelatedItemId: {Value: !GetAtt RelatedItem.RelatedItemId}
  RelatedItemRef: {Value: !Ref RelatedItem}
"""


@tags("axis:happy-path", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation provisions a Customer Profiles domain and a Cases template, case (naming a
    live profile) and comment, each read back by Ref and GetAtt through its own service;
    deleting the stacks removes every one of them.
    """
    cf = ctx.client("cloudformation")
    cc = ctx.client("connectcases")
    cp = ctx.client("customer-profiles")

    cases_domain_name = ctx.unique_name("sim2real-cfn-cases-domain-")
    profiles_domain_name = ctx.unique_name("sim2real-cfn-profiles-domain-")
    stack_a_id, outputs_a = _deploy_cfn(
        ctx, cf, _TEMPLATE_A,
        parameters={"CasesDomainName": cases_domain_name, "ProfilesDomainName": profiles_domain_name},
    )
    partition = stack_a_id.split(":")[1]
    cases_domain_id = outputs_a["CasesDomainId"]
    # Independent read: ListDomains by the declared name, never a read keyed by the outputs.
    listed = [(d["domainId"], d["domainArn"]) for d in _all_domains(cc)
              if d["name"] == cases_domain_name]
    assert listed == [(cases_domain_id, outputs_a["CasesDomainArn"])], (
        f"ListDomains entries named {cases_domain_name!r}: {listed!r}; GetAtt DomainId "
        f"{cases_domain_id!r}, DomainArn {outputs_a['CasesDomainArn']!r}"
    )
    assert outputs_a["ProfilesDomainRef"] == profiles_domain_name, (
        f"Ref should be the Customer Profiles domain's own name (its primary identifier), "
        f"got Ref={outputs_a['ProfilesDomainRef']!r} name={profiles_domain_name!r}"
    )
    profiles_domain = cp.get_domain(DomainName=outputs_a["ProfilesDomainRef"])
    assert profiles_domain["DomainName"] == profiles_domain_name, (
        f"expected GetDomain's DomainName {profiles_domain_name!r}, got {profiles_domain['DomainName']!r}"
    )
    assert profiles_domain["DefaultExpirationDays"] == 30, (
        f"expected DefaultExpirationDays 30, got {profiles_domain['DefaultExpirationDays']!r}"
    )
    cases_domain = cc.get_domain(domainId=cases_domain_id)
    assert outputs_a["CasesDomainRef"] == outputs_a["CasesDomainArn"] == cases_domain["domainArn"], (
        f"expected Ref and GetAtt DomainArn to be GetDomain's domainArn, got "
        f"Ref={outputs_a['CasesDomainRef']!r} GetAtt={outputs_a['CasesDomainArn']!r} "
        f"api={cases_domain['domainArn']!r}"
    )
    assert cases_domain["name"] == cases_domain_name, (
        f"expected Cases domain name {cases_domain_name!r}, got {cases_domain['name']!r}"
    )

    profile_id = cp.create_profile(DomainName=profiles_domain_name, FirstName="Sim2real")["ProfileId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile(DomainName=profiles_domain_name, ProfileId=profile_id),
            "ResourceNotFoundException",
        )
    )
    customer_arn = (
        f"arn:{partition}:profile:{ctx.region}:{ctx.account}:domains/{profiles_domain_name}/profiles/{profile_id}"
    )

    template_name = ctx.unique_name("sim2real-cfn-cases-template-")
    case_title = ctx.unique_name("sim2real-cfn-cases-case-")
    comment_body = ctx.unique_name("sim2real-cfn-cases-comment-")
    stack_b_id, outputs_b = _deploy_cfn(
        ctx, cf, _TEMPLATE_B,
        parameters={
            "CasesDomainId": cases_domain_id,
            "TemplateName": template_name,
            "CaseTitle": case_title,
            "CustomerArn": customer_arn,
            "CommentBody": comment_body,
        },
    )
    template_id = outputs_b["TemplateId"]
    case_id = outputs_b["CaseId"]
    related_item_id = outputs_b["RelatedItemId"]

    listed_templates = [(t["templateId"], t["templateArn"]) for t in _all_templates(
        cc, cases_domain_id) if t["name"] == template_name]
    assert listed_templates == [(template_id, outputs_b["TemplateRef"])], (
        f"ListTemplates entries named {template_name!r}: {listed_templates!r}; GetAtt TemplateId "
        f"{template_id!r}, Ref {outputs_b['TemplateRef']!r}"
    )
    template = cc.get_template(domainId=cases_domain_id, templateId=template_id)
    assert outputs_b["TemplateRef"] == template["templateArn"], (
        f"Ref should be the template's ARN, got Ref={outputs_b['TemplateRef']!r} "
        f"templateArn={template['templateArn']!r}"
    )
    assert template["name"] == template_name, f"expected template name {template_name!r}, got {template['name']!r}"
    assert template["status"] == "Active", f"expected template status 'Active', got {template['status']!r}"

    expected_case_arn = f"arn:{partition}:cases:{ctx.region}:{ctx.account}:domain/{cases_domain_id}/case/{case_id}"
    assert outputs_b["CaseRef"] == expected_case_arn, (
        f"expected Ref to be the case's ARN {expected_case_arn!r}, got {outputs_b['CaseRef']!r}"
    )
    case = cc.get_case(domainId=cases_domain_id, caseId=case_id, fields=[{"id": "title"}, {"id": "customer_id"}])
    case_fields = {f["id"]: f["value"]["stringValue"] for f in case["fields"]}
    assert case_fields.get("title") == case_title, f"expected case title {case_title!r}, got {case_fields.get('title')!r}"
    assert case_fields.get("customer_id") == customer_arn, (
        f"expected case customer_id {customer_arn!r}, got {case_fields.get('customer_id')!r}"
    )
    assert case["templateId"] == template_id, f"expected case templateId {template_id!r}, got {case['templateId']!r}"

    related = _all_related_items(cc, cases_domain_id, case_id)
    matching = [r for r in related if r["relatedItemId"] == related_item_id]
    assert len(matching) == 1, f"expected exactly one related item {related_item_id!r}, got {related!r}"
    related_item = matching[0]
    assert related_item["type"] == "Comment", f"expected related item type 'Comment', got {related_item['type']!r}"
    assert related_item["content"]["comment"] == {"body": comment_body, "contentType": "Text/Plain"}, (
        f"expected comment content {{'body': {comment_body!r}, 'contentType': 'Text/Plain'}}, "
        f"got {related_item['content']['comment']!r}"
    )
    expected_related_item_arn = (
        f"arn:{partition}:cases:{ctx.region}:{ctx.account}:domain/{cases_domain_id}/case/{case_id}"
        f"/related-item/{related_item_id}"
    )
    assert outputs_b["RelatedItemRef"] == expected_related_item_arn, (
        f"expected Ref to be the related item's ARN {expected_related_item_arn!r}, "
        f"got {outputs_b['RelatedItemRef']!r}"
    )

    delete_stack(cf, stack_b_id)

    template_after = cc.get_template(domainId=cases_domain_id, templateId=template_id)
    assert template_after["deleted"] is True, (
        f"expected GetTemplate on a deleted template to report deleted=True, got {template_after.get('deleted')!r}"
    )
    assert template_after["name"] == template_name, (
        f"expected the tombstoned template to keep its name {template_name!r}, "
        f"got {template_after['name']!r}"
    )

    case_gone = ("ResourceNotFoundException", f"A case with id '{case_id}' could not be found.")
    expect_error(
        lambda: cc.get_case(domainId=cases_domain_id, caseId=case_id, fields=[{"id": "title"}]),
        *case_gone,
    )
    expect_error(lambda: cc.search_related_items(domainId=cases_domain_id, caseId=case_id),
                 *_RELATED_CASE_NOT_FOUND)

    cp.delete_profile(DomainName=profiles_domain_name, ProfileId=profile_id)
    delete_stack(cf, stack_a_id)

    expect_error(lambda: cc.get_domain(domainId=cases_domain_id), *_CASES_NOT_FOUND)
    profiles_gone = ("ResourceNotFoundException", f"Domain {profiles_domain_name} is not found")
    expect_error(lambda: cp.get_domain(DomainName=profiles_domain_name), *profiles_gone)


def _all_domains(cc) -> list[dict]:
    """Every page of ListDomains; the account can hold more domains than one page."""
    out, token = [], None
    while True:
        page = cc.list_domains(**({"nextToken": token} if token else {}))
        out.extend(page.get("domains", []))
        token = page.get("nextToken")
        if not token:
            return out


def _all_templates(cc, domain_id) -> list[dict]:
    """Every page of ListTemplates for the domain."""
    out, token = [], None
    while True:
        page = cc.list_templates(domainId=domain_id, **({"nextToken": token} if token else {}))
        out.extend(page.get("templates", []))
        token = page.get("nextToken")
        if not token:
            return out


def _all_related_items(cc, domain_id, case_id) -> list[dict]:
    """Every page of SearchRelatedItems for the case."""
    out, token = [], None
    while True:
        page = cc.search_related_items(
            domainId=domain_id, caseId=case_id, **({"nextToken": token} if token else {})
        )
        out.extend(page.get("relatedItems", []))
        token = page.get("nextToken")
        if not token:
            return out


def _ignore_not_found(fn, *not_found: str):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in not_found:
            raise


def _deploy_cfn(ctx, cf, template: str, *, parameters: dict[str, str]) -> tuple[str, dict]:
    """create_stack, then CREATE_COMPLETE; return ``(stack_id, outputs)``."""
    stack_id = create_stack(
        ctx, cf, ctx.unique_name("sim2real-cfn-cases-stack-"), template,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"expected stack {stack_id} CREATE_COMPLETE, got {status!r}: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )
    return stack_id, stack_outputs(cf, stack_id)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
