"""deploy-cfn-cases-domain-field-caserule-layout-provisions-live-resources."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-cases-domain-field-caserule-layout-provisions-live-resources"
GROUP = "deploy"
SERVICES = ["cloudformation", "connectcases"]

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


# ---- Check-specific: the template, then run(). ----

_NOT_FOUND = ("ResourceNotFoundException", "Requested resource not found.")

#: A Cases domain with a custom field, a case rule conditioned on that field, and a layout
#: that places the field in its top panel.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: A Cases domain with a custom field, a case rule and a layout.
Parameters:
  DomainName: {Type: String}
  FieldName: {Type: String}
  RuleName: {Type: String}
  LayoutName: {Type: String}
Resources:
  Domain:
    Type: AWS::Cases::Domain
    Properties:
      Name: !Ref DomainName
  Field:
    Type: AWS::Cases::Field
    Properties:
      DomainId: !GetAtt Domain.DomainId
      Name: !Ref FieldName
      Type: Text
  CaseRule:
    Type: AWS::Cases::CaseRule
    Properties:
      DomainId: !GetAtt Domain.DomainId
      Name: !Ref RuleName
      Rule:
        Required:
          DefaultValue: false
          Conditions:
            - EqualTo:
                OperandOne:
                  FieldId: !GetAtt Field.FieldId
                OperandTwo:
                  StringValue: trigger
                Result: true
  Layout:
    Type: AWS::Cases::Layout
    Properties:
      DomainId: !GetAtt Domain.DomainId
      Name: !Ref LayoutName
      Content:
        Basic:
          TopPanel:
            Sections:
              - FieldGroup:
                  Fields:
                    - Id: !GetAtt Field.FieldId
Outputs:
  DomainId: {Value: !GetAtt Domain.DomainId}
  DomainArn: {Value: !GetAtt Domain.DomainArn}
  DomainRef: {Value: !Ref Domain}
  FieldId: {Value: !GetAtt Field.FieldId}
  FieldRef: {Value: !Ref Field}
  FieldNamespace: {Value: !GetAtt Field.Namespace}
  CaseRuleId: {Value: !GetAtt CaseRule.CaseRuleId}
  CaseRuleRef: {Value: !Ref CaseRule}
  LayoutId: {Value: !GetAtt Layout.LayoutId}
  LayoutRef: {Value: !Ref Layout}
"""


def _all_pages(fn, key: str, **kw) -> list[dict]:
    """Every item under ``key`` across all nextToken pages (botocore ships no paginator)."""
    items = []
    while True:
        page = fn(**kw)
        items.extend(page.get(key, []))
        if not page.get("nextToken"):
            return items
        kw["nextToken"] = page["nextToken"]


@tags("axis:happy-path", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack really provisions a Cases domain, field, case rule and layout:
    each Ref is the resource's own ARN, each GetAtt attribute and template property reads
    back through ConnectCases, and deleting the stack removes every one of them.
    """
    cf = ctx.client("cloudformation")
    cc = ctx.client("connectcases")
    domain_name = ctx.unique_name("sim2real-cfn-cases-domain-")
    field_name = ctx.unique_name("sim2real-cfn-cases-field-")
    rule_name = ctx.unique_name("sim2real-cfn-cases-rule-")
    layout_name = ctx.unique_name("sim2real-cfn-cases-layout-")

    parameters = {
        "DomainName": domain_name,
        "FieldName": field_name,
        "RuleName": rule_name,
        "LayoutName": layout_name,
    }
    stack_id = create_stack(
        ctx, cf, ctx.unique_name("sim2real-cfn-cases-stack-"), _TEMPLATE,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    domain_id = outputs["DomainId"]
    field_id = outputs["FieldId"]
    rule_id = outputs["CaseRuleId"]
    layout_id = outputs["LayoutId"]

    # Independent read: ListDomains by the declared name, never a read keyed by the outputs.
    listed = [(d["domainId"], d["domainArn"]) for d in _all_pages(cc.list_domains, "domains")
              if d["name"] == domain_name]
    assert listed == [(domain_id, outputs["DomainArn"])], (
        f"ListDomains entries named {domain_name!r}: {listed!r}; GetAtt DomainId "
        f"{domain_id!r}, DomainArn {outputs['DomainArn']!r}"
    )
    domain = cc.get_domain(domainId=domain_id)
    assert outputs["DomainRef"] == outputs["DomainArn"], (
        f"Ref should be the domain's ARN (its primary identifier), got Ref={outputs['DomainRef']!r} "
        f"GetAtt DomainArn={outputs['DomainArn']!r}"
    )
    assert domain["domainArn"] == outputs["DomainArn"], (
        f"GetAtt DomainArn {outputs['DomainArn']!r} does not match GetDomain's domainArn "
        f"{domain['domainArn']!r}"
    )
    assert domain["domainStatus"] == "Active", f"expected an Active domain, got {domain['domainStatus']!r}"
    assert domain["name"] == domain_name, f"expected domain name {domain_name!r}, got {domain['name']!r}"

    listed_fields = [f["fieldId"] for f in _all_pages(cc.list_fields, "fields", domainId=domain_id)
                     if f["name"] == field_name]
    assert listed_fields == [field_id], (
        f"ListFields entries named {field_name!r}: {listed_fields!r}; GetAtt FieldId {field_id!r}"
    )
    fields = cc.batch_get_field(domainId=domain_id, fields=[{"id": field_id}])["fields"]
    assert len(fields) == 1, f"expected exactly one field for {field_id!r}, got {fields!r}"
    field = fields[0]
    assert outputs["FieldRef"] == field["fieldArn"], (
        f"Ref should be the field's ARN, got Ref={outputs['FieldRef']!r} fieldArn={field['fieldArn']!r}"
    )
    assert field["name"] == field_name, f"expected field name {field_name!r}, got {field['name']!r}"
    assert field["type"] == "Text", f"expected field type 'Text', got {field['type']!r}"
    assert outputs["FieldNamespace"] == field["namespace"] == "Custom", (
        f"expected GetAtt Namespace and BatchGetField namespace both 'Custom', "
        f"got GetAtt={outputs['FieldNamespace']!r} api={field['namespace']!r}"
    )

    listed_rules = [(r["caseRuleId"], r["caseRuleArn"])
                    for r in _all_pages(cc.list_case_rules, "caseRules", domainId=domain_id)
                    if r["name"] == rule_name]
    assert listed_rules == [(rule_id, outputs["CaseRuleRef"])], (
        f"ListCaseRules entries named {rule_name!r}: {listed_rules!r}; GetAtt CaseRuleId "
        f"{rule_id!r}, Ref {outputs['CaseRuleRef']!r}"
    )
    rules = cc.batch_get_case_rule(domainId=domain_id, caseRules=[{"id": rule_id}])["caseRules"]
    assert len(rules) == 1, f"expected exactly one case rule for {rule_id!r}, got {rules!r}"
    rule = rules[0]
    assert outputs["CaseRuleRef"] == rule["caseRuleArn"], (
        f"Ref should be the case rule's ARN, got Ref={outputs['CaseRuleRef']!r} "
        f"caseRuleArn={rule['caseRuleArn']!r}"
    )
    assert rule["name"] == rule_name, f"expected case rule name {rule_name!r}, got {rule['name']!r}"
    expected_rule = {
        "required": {
            "defaultValue": False,
            "conditions": [
                {"equalTo": {
                    "operandOne": {"fieldId": field_id},
                    "operandTwo": {"stringValue": "trigger"},
                    "result": True,
                }}
            ],
        }
    }
    assert rule["rule"] == expected_rule, f"expected rule body {expected_rule!r}, got {rule['rule']!r}"

    listed_layouts = [(x["layoutId"], x["layoutArn"])
                      for x in _all_pages(cc.list_layouts, "layouts", domainId=domain_id)
                      if x["name"] == layout_name]
    assert listed_layouts == [(layout_id, outputs["LayoutRef"])], (
        f"ListLayouts entries named {layout_name!r}: {listed_layouts!r}; GetAtt LayoutId "
        f"{layout_id!r}, Ref {outputs['LayoutRef']!r}"
    )
    layout = cc.get_layout(domainId=domain_id, layoutId=layout_id)
    assert outputs["LayoutRef"] == layout["layoutArn"], (
        f"Ref should be the layout's ARN, got Ref={outputs['LayoutRef']!r} layoutArn={layout['layoutArn']!r}"
    )
    assert layout["name"] == layout_name, f"expected layout name {layout_name!r}, got {layout['name']!r}"
    top_fields = layout["content"]["basic"]["topPanel"]["sections"][0]["fieldGroup"]["fields"]
    assert top_fields == [{"id": field_id}], f"expected top panel fields [{{'id': {field_id!r}}}], got {top_fields!r}"

    delete_stack(cf, stack_id)
    deleted = {e["LogicalResourceId"] for e in stack_events(cf, stack_id)
               if e["ResourceStatus"] == "DELETE_COMPLETE"}
    assert {"Domain", "Field", "CaseRule", "Layout"} <= deleted, (
        f"expected a DELETE_COMPLETE event for each of Domain, Field, CaseRule and Layout, "
        f"got {sorted(deleted)!r}"
    )

    expect_error(lambda: cc.get_domain(domainId=domain_id), *_NOT_FOUND)
    expect_error(lambda: cc.batch_get_field(domainId=domain_id, fields=[{"id": field_id}]),
                 *_NOT_FOUND)
    expect_error(lambda: cc.batch_get_case_rule(domainId=domain_id, caseRules=[{"id": rule_id}]),
                 *_NOT_FOUND)
    expect_error(lambda: cc.get_layout(domainId=domain_id, layoutId=layout_id), *_NOT_FOUND)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
