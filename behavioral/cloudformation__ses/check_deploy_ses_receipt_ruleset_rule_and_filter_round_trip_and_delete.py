"""deploy-ses-receipt-ruleset-rule-and-filter-round-trip-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ses-receipt-ruleset-rule-and-filter-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ses"]

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

_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RuleSetNameParam:
    Type: String
  RuleNameParam:
    Type: String
  FilterNameParam:
    Type: String
Resources:
  RuleSet:
    Type: AWS::SES::ReceiptRuleSet
    Properties:
      RuleSetName: !Ref RuleSetNameParam
{rule}  Filter:
    Type: AWS::SES::ReceiptFilter
    Properties:
      Filter:
        Name: !Ref FilterNameParam
        IpFilter:
          Policy: Block
          Cidr: 192.0.2.0/24
Outputs:
  RuleSetRefOut:
    Value: !Ref RuleSet
{rule_outputs}  FilterRefOut:
    Value: !Ref Filter
"""

_RULE = """  Rule:
    Type: AWS::SES::ReceiptRule
    DependsOn: RuleSet
    Properties:
      RuleSetName: !Ref RuleSetNameParam
      Rule:
        Name: !Ref RuleNameParam
        Enabled: false
        ScanEnabled: false
        Actions: []
"""
_RULE_OUTPUTS = """  RuleRefOut:
    Value: !Ref Rule
  RuleNameAttOut:
    Value: !GetAtt Rule.RuleName
"""


def _template(with_rule: bool) -> str:
    return _TEMPLATE_BODY.format(rule=_RULE if with_rule else "",
                                 rule_outputs=_RULE_OUTPUTS if with_rule else "")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ReceiptRuleSet, ReceiptRule and ReceiptFilter deployed by CloudFormation exist in SES with
    the template's properties; dropping the Rule deletes it from its live rule set, and deleting
    the stack removes the rule set and the filter."""
    cf = ctx.client("cloudformation")
    ses = ctx.client("ses")

    stack_name = ctx.unique_name("sim2real-cfn-ses-")
    rule_set_name = ctx.unique_name("sim2real-cfn-ses-rs-")
    rule_name = ctx.unique_name("sim2real-cfn-ses-rule-")
    filter_name = ctx.unique_name("sim2real-cfn-ses-filter-")

    params = [
        {"ParameterKey": "RuleSetNameParam", "ParameterValue": rule_set_name},
        {"ParameterKey": "RuleNameParam", "ParameterValue": rule_name},
        {"ParameterKey": "FilterNameParam", "ParameterValue": filter_name},
    ]
    stack_id = create_stack(ctx, cf, stack_name, _template(True), Parameters=params)
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack create ended in {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    assert outputs["RuleSetRefOut"] == rule_set_name, (
        f"Ref RuleSet {outputs['RuleSetRefOut']!r} != {rule_set_name!r}"
    )
    assert outputs["RuleRefOut"] == outputs["RuleNameAttOut"] == rule_name, (
        f"Ref/GetAtt Rule {outputs['RuleRefOut']!r}/{outputs['RuleNameAttOut']!r} != {rule_name!r}"
    )
    assert outputs["FilterRefOut"] == filter_name, (
        f"Ref Filter {outputs['FilterRefOut']!r} != {filter_name!r}"
    )

    rule_set = ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
    assert rule_set["Metadata"]["Name"] == rule_set_name, (
        f"expected DescribeReceiptRuleSet Name {rule_set_name!r}, got {rule_set['Metadata']!r}"
    )
    rule_names = [r["Name"] for r in rule_set["Rules"]]
    assert rule_names == [rule_name], (
        f"expected the rule set to carry exactly [{rule_name!r}], got {rule_names!r}"
    )

    rule = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert rule["Name"] == rule_name, f"expected rule name {rule_name!r}, got {rule['Name']!r}"
    assert rule["Enabled"] is False, f"expected Enabled False, got {rule['Enabled']!r}"
    assert rule["ScanEnabled"] is False, f"expected ScanEnabled False, got {rule['ScanEnabled']!r}"
    assert rule["Actions"] == [], f"expected no actions, got {rule['Actions']!r}"

    filters = ses.list_receipt_filters()["Filters"]
    by_name = {f["Name"]: f for f in filters}
    assert filter_name in by_name, (
        f"expected filter {filter_name!r} among ListReceiptFilters, got {sorted(by_name)!r}"
    )
    assert by_name[filter_name]["IpFilter"] == {"Policy": "Block", "Cidr": "192.0.2.0/24"}, (
        f"unexpected IpFilter {by_name[filter_name]['IpFilter']!r}"
    )

    # The Rule's own delete: drop it from the stack while its rule set stays.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(False), Parameters=params)
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"the Rule-dropping update ended {status!r}"
    rule_not_found = ("RuleDoesNotExist", f"Rule does not exist: {rule_name}")
    expect_error(lambda: ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name),
                 *rule_not_found)
    rules_left = ses.describe_receipt_rule_set(RuleSetName=rule_set_name)["Rules"]
    assert rules_left == [], f"the live rule set still carries rules {rules_left!r}"

    delete_stack(cf, stack_id)

    rule_set_not_found = ("RuleSetDoesNotExist", f"Rule set does not exist: {rule_set_name}")
    expect_error(lambda: ses.describe_receipt_rule_set(RuleSetName=rule_set_name), *rule_set_not_found)

    filters_after = ses.list_receipt_filters()["Filters"]
    names_after = {f["Name"] for f in filters_after}
    assert filter_name not in names_after, (
        f"expected {filter_name!r} gone from ListReceiptFilters, got {sorted(names_after)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
