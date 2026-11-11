"""deploy-securityhub-automationrulev2-invalid-ruleorder-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-securityhub-automationrulev2-invalid-ruleorder-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "securityhub"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_REJECTED = [(
    "Rule", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "#/RuleOrder: 0 is not greater or equal to 1.0", "/Resources/Rule/Properties/RuleOrder",
)]
_DESCRIPTION = "sim2real automation rule for a validation check"
_ACTIONS = [{"Type": "FINDING_FIELDS_UPDATE",
             "FindingFieldsUpdate": {"Comment": "sim2real rule action"}}]


def _template(rule_name: str, rule_order: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Hub": {"Type": "AWS::SecurityHub::HubV2", "Properties": {}},
            "Rule": {
                "Type": "AWS::SecurityHub::AutomationRuleV2",
                "DependsOn": "Hub",
                "Properties": {
                    "RuleName": rule_name,
                    "Description": _DESCRIPTION,
                    "RuleOrder": rule_order,
                    "Criteria": {"OcsfFindingCriteria": {"CompositeFilters": [{
                        "StringFilters": [{
                            "FieldName": "finding_info.title",
                            "Filter": {"Value": rule_name, "Comparison": "EQUALS"},
                        }],
                    }]}},
                    "Actions": _ACTIONS,
                },
            },
        },
        "Outputs": {"RuleArn": {"Value": {"Ref": "Rule"}}},
    })


def _require_hub_v2_off(sh):
    """Precondition: HubV2 is off here, so deleting the control stack restores the prior state."""
    try:
        hub = sh.describe_security_hub_v2()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    raise AssertionError(
        f"precondition: Security Hub v2 is already enabled in this region ({hub.get('HubV2Arn')!r});"
        " this check enables it through a stack and deletes it, so it needs it off"
    )


def _rules(sh):
    """Every ListAutomationRulesV2 entry across NextToken pages (the operation has no paginator)."""
    out, kw = [], {}
    while True:
        page = sh.list_automation_rules_v2(**kw)
        out += page.get("Rules", [])
        if not page.get("NextToken"):
            return out
        kw = {"NextToken": page["NextToken"]}


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
      "resource:account-singleton:securityhub-v2")
def run(ctx) -> None:
    """A CloudFormation AWS::SecurityHub::AutomationRuleV2 with RuleOrder below 1 fails early
    property validation and SecurityHub never holds it, while the same template with RuleOrder 5
    deploys and the rule reads back through SecurityHub.
    """
    cfn = ctx.client("cloudformation")
    sh = ctx.client("securityhub")
    _require_hub_v2_off(sh)
    bad_rule_name = ctx.unique_name("sim2real-shv2rej-bad-rule-")
    good_rule_name = ctx.unique_name("sim2real-shv2rej-good-rule-")

    # The rejected stack runs first: refused before any resource, it never enables HubV2.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-shv2rej-bad-"),
                          _template(bad_rule_name, 0))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"stack with RuleOrder=0 ended {status!r}"
    rows = [r for r in validation_rows(cfn, bad_id) if r[3] == "FAIL"]
    assert rows == _REJECTED, f"VALIDATION_ERROR rows {rows!r}, expected {_REJECTED!r}"

    # Positive control: the same template with RuleOrder 5 deploys, and the rule reads back.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-shv2rej-good-"),
                           _template(good_rule_name, 5))
    status = wait_stack(cfn, good_id, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    rule_arn = stack_outputs(cfn, good_id)["RuleArn"]
    rule = sh.get_automation_rule_v2(Identifier=rule_arn)
    got = (rule.get("RuleArn"), rule.get("RuleName"), rule.get("RuleOrder"),
           rule.get("Description"), rule.get("Actions"))
    want = (rule_arn, good_rule_name, 5.0, _DESCRIPTION, _ACTIONS)
    assert got == want, f"control rule reads {got!r}, expected {want!r}"

    # SecurityHub holds the control's rule and never the rejected one.
    names = {r.get("RuleName") for r in _rules(sh)}
    got = (good_rule_name in names, bad_rule_name in names)
    assert got == (True, False), f"(control listed, rejected listed) {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
