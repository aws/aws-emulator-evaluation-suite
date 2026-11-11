"""securityhub-hub-invalid-mode-rejected-and-children-round-trip."""
from __future__ import annotations

import json
import time
from datetime import timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "securityhub-hub-invalid-mode-rejected-and-children-round-trip"
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

def _hub_only_template(control_finding_generator: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Hub": {
                "Type": "AWS::SecurityHub::Hub",
                "Properties": {
                    "EnableDefaultStandards": False,
                    "ControlFindingGenerator": control_finding_generator,
                    "Tags": {"sim2real-resource": tag_value},
                },
            },
        },
        "Outputs": {"HubRef": {"Value": {"Ref": "Hub"}}},
    })


def _full_template(*, action_target_id: str, action_target_name: str, insight_name: str,
                    rule_name: str, linked_region: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Hub": {
                "Type": "AWS::SecurityHub::Hub",
                "Properties": {
                    "EnableDefaultStandards": False,
                    "ControlFindingGenerator": "SECURITY_CONTROL",
                    "Tags": {"sim2real-resource": tag_value},
                },
            },
            "ActionTarget": {
                "Type": "AWS::SecurityHub::ActionTarget",
                "DependsOn": "Hub",
                "Properties": {
                    "Name": action_target_name,
                    "Description": f"{tag_value} action target",
                    "Id": action_target_id,
                },
            },
            "Insight": {
                "Type": "AWS::SecurityHub::Insight",
                "DependsOn": "Hub",
                "Properties": {
                    "Name": insight_name,
                    "GroupByAttribute": "ResourceType",
                    "Filters": {"SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}]},
                },
            },
            "AutomationRule": {
                "Type": "AWS::SecurityHub::AutomationRule",
                "DependsOn": "Hub",
                "Properties": {
                    "RuleName": rule_name,
                    "RuleOrder": 1,
                    "Description": f"{tag_value} automation rule",
                    "Criteria": {"ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]},
                    "Actions": [{
                        "Type": "FINDING_FIELDS_UPDATE",
                        "FindingFieldsUpdate": {"Note": {"Text": f"{tag_value} note", "UpdatedBy": tag_value}},
                    }],
                    # No template Tags: CloudFormation refuses the key "sim2real-resource"
                    # (PROPERTY_VALIDATION "Unsupported property [sim2real-resource]" at
                    # /Resources/AutomationRule/Properties/Tags; this type's keys are [a-zA-Z0-9]).
                },
            },
            "FindingAggregator": {
                "Type": "AWS::SecurityHub::FindingAggregator",
                "DependsOn": "Hub",
                "Properties": {
                    "RegionLinkingMode": "SPECIFIED_REGIONS",
                    "Regions": [linked_region],
                },
            },
            "ProductSubscription": {
                "Type": "AWS::SecurityHub::ProductSubscription",
                "DependsOn": "Hub",
                "Properties": {
                    "ProductArn": {
                        "Fn::Sub": "arn:${AWS::Partition}:securityhub:${AWS::Region}::product/aws/"
                                   "iot-device-defender-audit"
                    },
                },
            },
            # Every standard bills per control evaluation; this one is enabled only for the
            # minutes between this update and the child-dropping one.
            "Standard": {
                "Type": "AWS::SecurityHub::Standard",
                "DependsOn": "Hub",
                "Properties": {
                    "StandardsArn": {
                        "Fn::Sub": "arn:${AWS::Partition}:securityhub:${AWS::Region}::standards/"
                                   "aws-foundational-security-best-practices/v/1.0.0"
                    },
                },
            },
        },
        "Outputs": {
            "HubRef": {"Value": {"Ref": "Hub"}},
            "HubArn": {"Value": {"Fn::GetAtt": ["Hub", "ARN"]}},
            "HubSubscribedAt": {"Value": {"Fn::GetAtt": ["Hub", "SubscribedAt"]}},
            "ActionTargetArn": {"Value": {"Ref": "ActionTarget"}},
            "InsightArn": {"Value": {"Ref": "Insight"}},
            "AutomationRuleArn": {"Value": {"Ref": "AutomationRule"}},
            "AutomationRuleCreatedAt": {"Value": {"Fn::GetAtt": ["AutomationRule", "CreatedAt"]}},
            "AutomationRuleCreatedBy": {"Value": {"Fn::GetAtt": ["AutomationRule", "CreatedBy"]}},
            "FindingAggregatorArn": {"Value": {"Ref": "FindingAggregator"}},
            "FindingAggregationRegion": {"Value": {"Fn::GetAtt": ["FindingAggregator", "FindingAggregationRegion"]}},
            "ProductSubscriptionArn": {"Value": {"Ref": "ProductSubscription"}},
            "StandardsSubscriptionArn": {"Value": {"Ref": "Standard"}},
        },
    })


def _iso_millis_z(dt) -> str:
    """A ``Timestamp`` shape's parsed ``datetime`` in the same ``...sssZ`` form CFN echoes."""
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _assert_hub_not_subscribed(sh, account):
    gone = ("InvalidAccessException", f"Account {account} is not subscribed to AWS Security Hub CSPM")
    expect_error(lambda: sh.describe_hub(), *gone)


def _automation_rules(sh):
    """Every ListAutomationRules entry (the operation has no botocore paginator)."""
    rules, kw = [], {}
    while True:
        page = sh.list_automation_rules(**kw)
        rules += page.get("AutomationRulesMetadata", [])
        if not page.get("NextToken"):
            return rules
        kw = {"NextToken": page["NextToken"]}


def _own_tags(sh, arn):
    tags_map = sh.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    return {k: v for k, v in tags_map.items() if not k.startswith("aws:")}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """A CloudFormation Security Hub hub with a malformed ControlFindingGenerator fails validation.

    The same template with SECURITY_CONTROL subscribes the hub; its seven child types read back,
    an update drops them while the hub answers, and the stack delete unsubscribes the account.
    """
    cfn = ctx.client("cloudformation")
    sh = ctx.client("securityhub")

    # Account singleton: the account must start unsubscribed, and the check leaves it so.
    _assert_hub_not_subscribed(sh, ctx.account)

    # Negative: an invalid ControlFindingGenerator, refused before Security Hub is reached.
    neg_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-shcfnneg-"),
                          _hub_only_template("BOGUS_MODE", CHECK))
    status = wait_stack(cfn, neg_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, neg_id)
    want_rows = [(
        "Hub", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "Property value [BOGUS_MODE] does not match pattern: ^(SECURITY_CONTROL|STANDARD_CONTROL)$",
        "/Resources/Hub/Properties/ControlFindingGenerator",
    )]
    assert rows == want_rows, f"validation rows {rows!r}, expected {want_rows!r}"
    _assert_hub_not_subscribed(sh, ctx.account)

    # Positive control: the same template with a VALID value subscribes the hub.
    stack = ctx.unique_name("sim2real-shcfn-")
    stack_id = create_stack(ctx, cfn, stack, _hub_only_template("SECURITY_CONTROL", CHECK))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    partition = stack_id.split(":")[1]
    hub = sh.describe_hub()
    hub_arn = f"arn:{partition}:securityhub:{ctx.region}:{ctx.account}:hub/default"
    assert (hub["HubArn"], stack_outputs(cfn, stack_id)["HubRef"]) == (hub_arn, hub_arn), (
        f"DescribeHub HubArn {hub['HubArn']!r}, expected {hub_arn!r}"
    )
    assert hub["ControlFindingGenerator"] == "SECURITY_CONTROL", f"hub reads {hub!r}"
    hub_tags = _own_tags(sh, hub_arn)
    assert hub_tags == {"sim2real": stack, "sim2real-resource": CHECK}, f"hub tags {hub_tags!r}"

    # Children: an update adds every child type; each reads back through Security Hub.
    action_target_id = ctx.unique_name("SH")
    action_target_name = ctx.unique_name("SHAT")
    insight_name = ctx.unique_name("sim2real-shcfn-ins-")
    rule_name = ctx.unique_name("sim2real-shcfn-rule-")
    # The finding aggregator needs a second, fixed linked region distinct from the home region:
    # a cross-region destination is picked explicitly, never derived from ctx.region.
    linked_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    cfn.update_stack(StackName=stack_id, TemplateBody=_full_template(
        action_target_id=action_target_id, action_target_name=action_target_name,
        insight_name=insight_name, rule_name=rule_name, linked_region=linked_region,
        tag_value=CHECK,
    ))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", (
        f"child-adding update ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    sh_prefix = f"arn:{partition}:securityhub:{ctx.region}"
    assert (outputs["HubRef"], outputs["HubArn"]) == (hub_arn, hub_arn), f"Hub Ref {outputs!r}"
    assert sh.describe_hub()["SubscribedAt"] == outputs["HubSubscribedAt"] == hub["SubscribedAt"], (
        f"GetAtt SubscribedAt {outputs['HubSubscribedAt']!r} != DescribeHub {hub['SubscribedAt']!r}"
    )

    # ActionTarget: Ref == the listed target carrying the templated name.
    at_arn = f"{sh_prefix}:{ctx.account}:action/custom/{action_target_id}"
    ats = [a for a in paginate(sh, "describe_action_targets", "ActionTargets")
           if a["Name"] == action_target_name]
    got = [(a["ActionTargetArn"], a["Description"]) for a in ats]
    assert got == [(at_arn, f"{CHECK} action target")], f"action targets {got!r}"
    assert outputs["ActionTargetArn"] == at_arn, f"ActionTarget Ref {outputs['ActionTargetArn']!r}"

    # Insight: Ref == the listed insight carrying the templated name; every property matches.
    insights = [i for i in paginate(sh, "get_insights", "Insights") if i["Name"] == insight_name]
    got = [(i["InsightArn"], i["GroupByAttribute"], i["Filters"]) for i in insights]
    want = [(outputs["InsightArn"], "ResourceType",
             {"SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}]})]
    assert got == want, f"insights {got!r}, expected {want!r}"

    # AutomationRule: Ref == the listed rule of that name; properties, GetAtts and the stack tag.
    listed = [r["RuleArn"] for r in _automation_rules(sh) if r["RuleName"] == rule_name]
    rule_arn = outputs["AutomationRuleArn"]
    assert listed == [rule_arn], f"ListAutomationRules found {listed!r}, Ref {rule_arn!r}"
    rule = sh.batch_get_automation_rules(AutomationRulesArns=[rule_arn])["Rules"][0]
    got = (rule["RuleOrder"], rule["Description"], rule["Criteria"],
           [(a["Type"], a["FindingFieldsUpdate"]["Note"]) for a in rule["Actions"]])
    want = (1, f"{CHECK} automation rule",
            {"ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]},
            [("FINDING_FIELDS_UPDATE", {"Text": f"{CHECK} note", "UpdatedBy": CHECK})])
    assert got == want, f"automation rule {got!r}, expected {want!r}"
    created_at = _iso_millis_z(rule["CreatedAt"])
    assert (created_at, rule["CreatedBy"]) == (
        outputs["AutomationRuleCreatedAt"], outputs["AutomationRuleCreatedBy"]
    ), f"rule CreatedAt/CreatedBy {(created_at, rule['CreatedBy'])!r} != the GetAtts"
    rule_tags = _own_tags(sh, rule_arn)
    assert rule_tags == {"sim2real": stack}, f"rule tags {rule_tags!r} (only the stack tag)"

    # FindingAggregator: Ref == the account's one listed aggregator; properties match.
    fa_arn = outputs["FindingAggregatorArn"]
    aggregators = [a["FindingAggregatorArn"]
                   for a in paginate(sh, "list_finding_aggregators", "FindingAggregators")]
    assert aggregators == [fa_arn], f"ListFindingAggregators {aggregators!r}, Ref {fa_arn!r}"
    fa = sh.get_finding_aggregator(FindingAggregatorArn=fa_arn)
    got = (fa["RegionLinkingMode"], fa["Regions"], fa["FindingAggregationRegion"])
    want = ("SPECIFIED_REGIONS", [linked_region], outputs["FindingAggregationRegion"])
    assert got == want and want[2] == ctx.region, f"finding aggregator {got!r}, expected {want!r}"

    # ProductSubscription and Standard: Ref == the documented ARN, listed by the account.
    ps_arn = f"{sh_prefix}:{ctx.account}:product-subscription/aws/iot-device-defender-audit"
    assert outputs["ProductSubscriptionArn"] == ps_arn, f"Ref {outputs['ProductSubscriptionArn']!r}"
    products = paginate(sh, "list_enabled_products_for_import", "ProductSubscriptions")
    assert [a for a in products if a == ps_arn] == [ps_arn], f"enabled products {products!r}"
    std_arn = f"{sh_prefix}:{ctx.account}:subscription/aws-foundational-security-best-practices/v/1.0.0"
    assert outputs["StandardsSubscriptionArn"] == std_arn, (
        f"Standard Ref {outputs['StandardsSubscriptionArn']!r} != {std_arn!r}"
    )
    standards = {s["StandardsSubscriptionArn"]: s["StandardsArn"]
                 for s in paginate(sh, "get_enabled_standards", "StandardsSubscriptions")}
    want_std = f"{sh_prefix}::standards/aws-foundational-security-best-practices/v/1.0.0"
    assert standards.get(std_arn) == want_std, f"enabled standards {standards!r}"

    # Children before the hub: an update back to the hub alone removes each while it answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_hub_only_template("SECURITY_CONTROL", CHECK))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    at_after = sh.describe_action_targets(ActionTargetArns=[at_arn])["ActionTargets"]
    assert at_after == [], f"ActionTarget {at_arn!r} still reported: {at_after!r}"
    insights_after = sh.get_insights(InsightArns=[outputs["InsightArn"]])["Insights"]
    assert insights_after == [], f"Insight still reported: {insights_after!r}"
    rules_after = sh.batch_get_automation_rules(AutomationRulesArns=[rule_arn])
    assert (rules_after["Rules"], rules_after["UnprocessedAutomationRules"]) == (
        [], [{"RuleArn": rule_arn, "ErrorCode": 404, "ErrorMessage": "ResourceNotFoundException"}]
    ), f"AutomationRule after the update: {rules_after!r}"
    gone = ("ResourceNotFoundException",
            f"A finding aggregator with the provided FindingAggregatorArn: {fa_arn} does not exist.")
    expect_error(lambda: sh.get_finding_aggregator(FindingAggregatorArn=fa_arn), *gone)
    products_after = paginate(sh, "list_enabled_products_for_import", "ProductSubscriptions")
    assert ps_arn not in products_after, f"{ps_arn!r} still enabled after the update"
    standards_after = [s["StandardsSubscriptionArn"]
                       for s in paginate(sh, "get_enabled_standards", "StandardsSubscriptions")]
    assert std_arn not in standards_after, f"{std_arn!r} still enabled after the update"
    assert sh.describe_hub()["SubscribedAt"] == hub["SubscribedAt"], "the hub was re-subscribed"

    # The stack delete unsubscribes the account, restoring its prior state.
    delete_stack(cfn, stack_id)
    _assert_hub_not_subscribed(sh, ctx.account)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
