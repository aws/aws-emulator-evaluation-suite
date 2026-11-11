"""deploy-rbin-rule-round-trip-then-stack-delete-confirms-removal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rbin-rule-round-trip-then-stack-delete-confirms-removal"
GROUP = "deploy"
SERVICES = ["cloudformation", "rbin"]

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


def _template(tag_key, tag_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Rule": {
                "Type": "AWS::Rbin::Rule",
                "Properties": {
                    "ResourceType": "EBS_SNAPSHOT",
                    "RetentionPeriod": {"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
                    "ResourceTags": [{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
                    "Tags": [{"Key": "sim2real-rbin", "Value": tag_value}],
                },
            },
        },
        "Outputs": {
            "RuleRef": {"Value": {"Ref": "Rule"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
            "RuleIdentifier": {"Value": {"Fn::GetAtt": ["Rule", "Identifier"]}},
            "RuleLockState": {"Value": {"Fn::GetAtt": ["Rule", "LockState"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation tag-level Recycle Bin rule reads back through Rbin -- Ref, every
    templated property, its own tag and the propagated stack tag -- and the stack delete removes it."""
    cf = ctx.client("cloudformation")
    rbin = ctx.client("rbin")
    stack = ctx.unique_name("sim2real-cfnrbin-rt-")
    tag_key = ctx.unique_name("sim2real-rbin-cfn-key-")
    tag_value = ctx.unique_name("sim2real-rbin-cfn-val-")

    stack_id = create_stack(ctx, cf, stack, _template(tag_key, tag_value))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Ref against an independent read (ListRules filtered by the scoping tag), never a read by
    # the Ref itself. The primary identifier is the rule ARN, so Ref == the listed RuleArn.
    listed = paginate(
        rbin, "list_rules", "Rules",
        ResourceType="EBS_SNAPSHOT", ResourceTags=[{"ResourceTagKey": tag_key,
                                                      "ResourceTagValue": tag_value}],
    )
    assert [r["Identifier"] for r in listed] == [out["RuleIdentifier"]], (
        f"ListRules found {listed!r} for Identifier {out['RuleIdentifier']!r}"
    )
    assert listed[0]["RuleArn"] == out["RuleRef"], (
        f"ListRules RuleArn {listed[0]['RuleArn']!r} != Ref {out['RuleRef']!r}"
    )
    # Read-only GetAtt Arn echoes Ref (both are the primary identifier).
    assert out["RuleArn"] == out["RuleRef"], f"GetAtt Arn {out['RuleArn']!r} != Ref {out['RuleRef']!r}"
    # ListRules omits LockState entirely for a rule that was never locked (the documented "null"
    # state); the CFN provider's GetAtt normalizes that same state to the string "unlocked".
    assert "LockState" not in listed[0], f"ListRules reports a LockState: {listed[0]!r}"
    assert out["RuleLockState"] == "unlocked", f"GetAtt LockState {out['RuleLockState']!r}"

    # Every templated property, read back through GetRule.
    rule = rbin.get_rule(Identifier=listed[0]["Identifier"])
    assert "LockState" not in rule, f"GetRule reports a LockState: {rule!r}"
    got = {
        "RuleArn": rule["RuleArn"],
        "ResourceType": rule["ResourceType"],
        "RetentionPeriod": rule["RetentionPeriod"],
        "ResourceTags": rule["ResourceTags"],
        "Status": rule["Status"],
    }
    assert got == {
        "RuleArn": out["RuleRef"],
        "ResourceType": "EBS_SNAPSHOT",
        "RetentionPeriod": {"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
        "ResourceTags": [{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
        "Status": "available",
    }, f"GetRule {got!r}"

    # The template tag and the propagated stack tag, CloudFormation's aws:* tags dropped.
    rule_tags = {t["Key"]: t["Value"]
                 for t in rbin.list_tags_for_resource(ResourceArn=rule["RuleArn"]).get("Tags", [])
                 if not t["Key"].startswith("aws:")}
    assert rule_tags == {"sim2real": stack, "sim2real-rbin": tag_value}, f"rule tags {rule_tags!r}"

    delete_stack(cf, stack_id)

    # Gone through Rbin: GetRule by the rule's own Identifier, and ListRules with the same filter
    # that found it a moment ago -- a filter that COULD still return it if the delete did nothing.
    not_found = ("ResourceNotFoundException",
                f"Recycle Bin Rule '{out['RuleIdentifier']}' does not exist.")
    expect_error(lambda: rbin.get_rule(Identifier=out["RuleIdentifier"]), *not_found)
    listed_after = paginate(
        rbin, "list_rules", "Rules",
        ResourceType="EBS_SNAPSHOT", ResourceTags=[{"ResourceTagKey": tag_key,
                                                      "ResourceTagValue": tag_value}],
    )
    assert listed_after == [], f"the deleted rule is still listed: {listed_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
