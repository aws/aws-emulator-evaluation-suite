"""deploy-medialive-eventbridge-rule-template-group-and-template-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-medialive-eventbridge-rule-template-group-and-template-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "medialive"]

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


# ---- Check-specific: the template, then run(). ----

def _template(group_name, template_name, description):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RuleGroup": {
                "Type": "AWS::MediaLive::EventBridgeRuleTemplateGroup",
                "Properties": {"Name": group_name},
            },
            "RuleTemplate": {
                "Type": "AWS::MediaLive::EventBridgeRuleTemplate",
                "Properties": {
                    "Name": template_name,
                    "Description": description,
                    "GroupIdentifier": {"Ref": "RuleGroup"},
                    "EventType": "MEDIALIVE_CHANNEL_STATE_CHANGE",
                },
            },
        },
        "Outputs": {
            "GroupId": {"Value": {"Ref": "RuleGroup"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["RuleGroup", "Arn"]}},
            "TemplateId": {"Value": {"Ref": "RuleTemplate"}},
            "TemplateArn": {"Value": {"Fn::GetAtt": ["RuleTemplate", "Arn"]}},
            "TemplateGroupId": {"Value": {"Fn::GetAtt": ["RuleTemplate", "GroupId"]}},
        },
    })


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EventBridgeRuleTemplateGroup and EventBridgeRuleTemplate read back through
    MediaLive with the template's values and Ids that match the paged lists by name; deleting the
    stack removes both from those lists.
    """
    cfn = ctx.client("cloudformation")
    medialive = ctx.client("medialive")
    group_name = ctx.unique_name("sim2real-behav-ebrtgroup-")
    template_name = ctx.unique_name("sim2real-behav-ebrt-")
    description = ctx.unique_name("sim2real-desc-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnmlebrt-"),
                            _template(group_name, template_name, description))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    group_id, template_id = out["GroupId"], out["TemplateId"]

    # Refs against the paged lists by name, never a read keyed by the Ref.
    groups = [g for g in paginate(medialive, "list_event_bridge_rule_template_groups",
                                  "EventBridgeRuleTemplateGroups") if g["Name"] == group_name]
    assert [g["Id"] for g in groups] == [group_id], f"group listing by name: {groups!r}"
    templates = [t for t in paginate(medialive, "list_event_bridge_rule_templates",
                                     "EventBridgeRuleTemplates") if t["Name"] == template_name]
    assert [t["Id"] for t in templates] == [template_id], f"template listing by name: {templates!r}"

    group = medialive.get_event_bridge_rule_template_group(Identifier=group_id)
    got = (group["Arn"], group["Name"])
    assert got == (out["GroupArn"], group_name), f"group reads {got!r}"

    tpl = medialive.get_event_bridge_rule_template(Identifier=template_id)
    got = (tpl["Arn"], tpl["GroupId"], tpl["Name"], tpl["Description"], tpl["EventType"])
    want = (out["TemplateArn"], groups[0]["Id"], template_name, description,
            "MEDIALIVE_CHANNEL_STATE_CHANGE")
    assert got == want, f"template reads {got!r}, expected {want!r}"
    assert out["TemplateGroupId"] == groups[0]["Id"], (
        f"GetAtt GroupId {out['TemplateGroupId']!r} != listed group Id {groups[0]['Id']!r}"
    )

    delete_stack(cfn, stack_id)
    template_ids = {t["Id"] for t in paginate(medialive, "list_event_bridge_rule_templates",
                                              "EventBridgeRuleTemplates")}
    assert template_id not in template_ids, f"the deleted template {template_id!r} is listed"
    group_ids = {g["Id"] for g in paginate(medialive, "list_event_bridge_rule_template_groups",
                                           "EventBridgeRuleTemplateGroups")}
    assert group_id not in group_ids, f"the deleted group {group_id!r} is listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
