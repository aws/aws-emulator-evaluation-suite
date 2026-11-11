"""deploy-securityhub-hubv2-aggregatorv2-rulev2-round-trip."""
from __future__ import annotations

import json
import time
from datetime import timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-securityhub-hubv2-aggregatorv2-rulev2-round-trip"
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

#: DescribeSecurityHubV2's own tombstone for the HubV2 this check's stack deletes.
_HUB_GONE = ("ResourceNotFoundException", "You are not subscribed to HubV2")
_DESCRIPTION = "sim2real automation rule for a CloudFormation round trip"


def _template(tag_value: str, rule_name: str, linked_region: str, children=True) -> str:
    resources = {"Hub": {
        "Type": "AWS::SecurityHub::HubV2",
        "Properties": {"Tags": {"sim2real-shv2": "hub"}},
    }}
    if children:
        resources["Aggregator"] = {
            "Type": "AWS::SecurityHub::AggregatorV2",
            "DependsOn": "Hub",
            "Properties": {
                "RegionLinkingMode": "SPECIFIED_REGIONS",
                "LinkedRegions": [linked_region],
                "Tags": {"sim2real-shv2": "aggregator"},
            },
        }
        resources["Rule"] = {
            "Type": "AWS::SecurityHub::AutomationRuleV2",
            "DependsOn": "Hub",
            "Properties": {
                "RuleName": rule_name,
                "Description": _DESCRIPTION,
                "RuleOrder": 5,
                "RuleStatus": "ENABLED",
                "Criteria": _criteria(tag_value),
                "Actions": _ACTIONS,
                "Tags": {"sim2real-shv2": "rule"},
            },
        }
    outputs = {
        "HubArn": {"Value": {"Ref": "Hub"}},
        "HubSubscribedAt": {"Value": {"Fn::GetAtt": "Hub.SubscribedAt"}},
    }
    if children:
        outputs.update({
            "AggregatorArn": {"Value": {"Ref": "Aggregator"}},
            "AggregatorAggregationRegion": {
                "Value": {"Fn::GetAtt": "Aggregator.AggregationRegion"}},
            "RuleArn": {"Value": {"Ref": "Rule"}},
            "RuleId": {"Value": {"Fn::GetAtt": "Rule.RuleId"}},
            "RuleCreatedAt": {"Value": {"Fn::GetAtt": "Rule.CreatedAt"}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _criteria(value):
    return {"OcsfFindingCriteria": {
        "CompositeFilters": [{"StringFilters": [{
            "FieldName": "finding_info.title",
            "Filter": {"Value": value, "Comparison": "EQUALS"},
        }]}],
        "CompositeOperator": "AND",
    }}


_ACTIONS = [{"Type": "FINDING_FIELDS_UPDATE",
             "FindingFieldsUpdate": {"Comment": "sim2real rule action"}}]


def _require_hub_v2_off(sh):
    """Precondition: HubV2 is off here, so deleting the stack restores the account's prior state."""
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


def _tags(sh, arn):
    return {k: v for k, v in sh.list_tags_for_resource(ResourceArn=arn).get("Tags", {}).items()
            if not k.startswith("aws:")}


def _iso_ms(dt) -> str:
    """A ``datetime`` as the millisecond ISO-8601 string CloudFormation's GetAtt returns."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control", "resource:account-singleton:securityhub-v2")
def run(ctx) -> None:
    """A CloudFormation stack provisions SecurityHub HubV2, AggregatorV2 and AutomationRuleV2; each
    Ref is the ARN SecurityHub lists, every property, tag and GetAtt reads back, an update dropping
    the aggregator and rule removes each while the same hub stays, and the delete turns HubV2 off.
    """
    sh = ctx.client("securityhub")
    cfn = ctx.client("cloudformation")
    _require_hub_v2_off(sh)
    stack = ctx.unique_name("sim2real-shv2-")
    rule_name = ctx.unique_name("sim2real-shv2-rule-")
    # The aggregator needs a second, fixed linked region distinct from the home region: a
    # cross-region destination is picked explicitly, never derived from ctx.region.
    linked_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK, rule_name, linked_region))
    status = wait_stack(cfn, stack_id, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    hub_arn, agg_arn, rule_arn = outputs["HubArn"], outputs["AggregatorArn"], outputs["RuleArn"]

    hub = sh.describe_security_hub_v2()
    got = (hub["HubV2Arn"], hub["SubscribedAt"])
    assert got == (hub_arn, outputs["HubSubscribedAt"]), (
        f"DescribeSecurityHubV2 (HubV2Arn, SubscribedAt) {got!r}, Ref/GetAtt "
        f"{(hub_arn, outputs['HubSubscribedAt'])!r}"
    )
    got = _tags(sh, hub_arn)
    assert got == {"sim2real": stack, "sim2real-shv2": "hub"}, f"hub tags {got!r}"

    listed = [a["AggregatorV2Arn"] for a in paginate(sh, "list_aggregators_v2", "AggregatorsV2")
              if a["AggregatorV2Arn"] == agg_arn]
    assert listed == [agg_arn], f"ListAggregatorsV2 {listed!r} for Ref {agg_arn!r}"
    agg = sh.get_aggregator_v2(AggregatorV2Arn=agg_arn)
    got = (agg["AggregationRegion"], agg["RegionLinkingMode"], agg["LinkedRegions"])
    want = (outputs["AggregatorAggregationRegion"], "SPECIFIED_REGIONS", [linked_region])
    assert got == want, f"aggregator (region, mode, linked) {got!r} != {want!r}"
    assert want[0] == ctx.region, f"GetAtt AggregationRegion {want[0]!r} != {ctx.region!r}"
    got = _tags(sh, agg_arn)
    assert got == {"sim2real": stack, "sim2real-shv2": "aggregator"}, f"aggregator tags {got!r}"

    listed = [(r["RuleArn"], r["RuleId"]) for r in _rules(sh) if r.get("RuleName") == rule_name]
    assert listed == [(rule_arn, outputs["RuleId"])], (
        f"ListAutomationRulesV2 {listed!r} for Ref {rule_arn!r}, GetAtt RuleId {outputs['RuleId']!r}"
    )
    rule = sh.get_automation_rule_v2(Identifier=rule_arn)
    got = {k: rule.get(k) for k in ("RuleArn", "RuleId", "RuleName", "RuleOrder", "RuleStatus",
                                     "Description", "Criteria", "Actions")}
    want = {"RuleArn": rule_arn, "RuleId": outputs["RuleId"], "RuleName": rule_name,
            "RuleOrder": 5.0, "RuleStatus": "ENABLED", "Description": _DESCRIPTION,
            "Criteria": _criteria(CHECK), "Actions": _ACTIONS}
    assert got == want, f"GetAutomationRuleV2 reads {got!r}, expected {want!r}"
    assert _iso_ms(rule["CreatedAt"]) == outputs["RuleCreatedAt"], (
        f"GetAutomationRuleV2 CreatedAt {rule['CreatedAt']!r} != GetAtt {outputs['RuleCreatedAt']!r}"
    )
    got = _tags(sh, rule_arn)
    assert got == {"sim2real": stack, "sim2real-shv2": "rule"}, f"rule tags {got!r}"

    # Children first: the update drops the aggregator and rule while the same hub (its
    # SubscribedAt unchanged) stays enabled, so each child's own delete is proven.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(CHECK, rule_name, linked_region, children=False))
    status = wait_stack(cfn, stack_id, timeout_s=900.0)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    gone = ("ResourceNotFoundException",
            f"An AggregatorV2 with the provided AggregatorV2Arn: {agg_arn} does not exist.")
    expect_error(lambda: sh.get_aggregator_v2(AggregatorV2Arn=agg_arn), *gone)
    gone = ("ResourceNotFoundException", "ResourceNotFound")
    expect_error(lambda: sh.get_automation_rule_v2(Identifier=rule_arn), *gone)
    still = sh.describe_security_hub_v2()
    got = (still["HubV2Arn"], still["SubscribedAt"])
    assert got == (hub_arn, hub["SubscribedAt"]), (
        f"after dropping the children the hub reads {got!r}, was {(hub_arn, hub['SubscribedAt'])!r}"
    )

    # Deleting the stack restores the precondition's state: HubV2 off.
    delete_stack(cfn, stack_id)
    expect_error(lambda: sh.describe_security_hub_v2(), *_HUB_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
