"""deploy-asg-lifecyclehook-scheduledaction-warmpool-provisioned-and-deleted."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-asg-lifecyclehook-scheduledaction-warmpool-provisioned-and-deleted"
GROUP = "deploy"
SERVICES = ["autoscaling", "cloudformation"]

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

_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _template(subnet_id, asg_name, hook_name, with_children=True):
    resources = {
        "LaunchTemplate": {
            "Type": "AWS::EC2::LaunchTemplate",
            "Properties": {
                "LaunchTemplateData": {"ImageId": {"Ref": "ImageId"}, "InstanceType": "t3.micro"},
            },
        },
        "ASG": {
            "Type": "AWS::AutoScaling::AutoScalingGroup",
            "Properties": {
                "AutoScalingGroupName": asg_name,
                "MinSize": "0",
                "MaxSize": "1",
                "DesiredCapacity": "0",
                "VPCZoneIdentifier": [subnet_id],
                "LaunchTemplate": {
                    "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                    "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                },
            },
        },
    }
    outputs = {
        "AsgRef": {"Value": {"Ref": "ASG"}},
        "LaunchTemplateId": {"Value": {"Ref": "LaunchTemplate"}},
        "LaunchTemplateVersion": {"Value": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]}},
    }
    if with_children:
        resources["LifecycleHook"] = {
            "Type": "AWS::AutoScaling::LifecycleHook",
            "Properties": {
                "AutoScalingGroupName": {"Ref": "ASG"},
                "LifecycleHookName": hook_name,
                "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
                "HeartbeatTimeout": 60,
                "DefaultResult": "ABANDON",
            },
        }
        resources["ScheduledAction"] = {
            "Type": "AWS::AutoScaling::ScheduledAction",
            "Properties": {
                "AutoScalingGroupName": {"Ref": "ASG"},
                "Recurrence": "0 0 1 1 *",
                "MinSize": 0,
                "MaxSize": 1,
            },
        }
        resources["WarmPool"] = {
            "Type": "AWS::AutoScaling::WarmPool",
            "Properties": {
                "AutoScalingGroupName": {"Ref": "ASG"},
                "MinSize": 0,
                "MaxGroupPreparedCapacity": 0,
                "PoolState": "Stopped",
            },
        }
        outputs["HookRef"] = {"Value": {"Ref": "LifecycleHook"}}
        outputs["ScheduledActionRef"] = {"Value": {"Ref": "ScheduledAction"}}
        outputs["ScheduledActionNameAtt"] = {
            "Value": {"Fn::GetAtt": ["ScheduledAction", "ScheduledActionName"]}
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        # The public AMI parameter resolves inside CloudFormation, not through a check call.
        "Parameters": {"ImageId": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                                   "Default": _AMI_PARAMETER}},
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ASG, LifecycleHook, ScheduledAction and WarmPool each read back through
    AutoScaling with their templated properties, and deleting the stack removes all four.
    """
    cf = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")

    subnet_id = ctx.network().subnet_ids[0]
    stack = ctx.unique_name("sim2real-cfnasg-rt-")
    asg_name = ctx.unique_name("sim2real-cfnasg-rt-asg-")
    hook_name = ctx.unique_name("sim2real-cfnasg-rt-hook-")

    stack_id = create_stack(ctx, cf, stack, _template(subnet_id, asg_name, hook_name, True))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    assert out["AsgRef"] == asg_name, f"Ref ASG {out['AsgRef']!r} != {asg_name!r}"

    # The ASG and its templated properties, from a read by the templated name.
    groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert len(groups) == 1, f"expected exactly one ASG named {asg_name!r}, got {groups!r}"
    group = groups[0]
    got = (group["MinSize"], group["MaxSize"], group["DesiredCapacity"],
           group["VPCZoneIdentifier"], group.get("LaunchTemplate", {}).get("LaunchTemplateId"),
           group.get("LaunchTemplate", {}).get("Version"))
    want = (0, 1, 0, subnet_id, out["LaunchTemplateId"], out["LaunchTemplateVersion"])
    assert got == want, f"ASG {asg_name!r} reads {got!r}, expected {want!r}"
    created = group["CreatedTime"]

    # LifecycleHook: Ref == the hook's own name, independently listed for the ASG it owns (no
    # LifecycleHookNames filter, so this is not a read keyed by the Ref), and every property the
    # template set reads back through DescribeLifecycleHooks.
    assert out["HookRef"] == hook_name, f"Ref LifecycleHook {out['HookRef']!r} != {hook_name!r}"
    hooks = asgc.describe_lifecycle_hooks(AutoScalingGroupName=asg_name)["LifecycleHooks"]
    assert [h["LifecycleHookName"] for h in hooks] == [hook_name], (
        f"DescribeLifecycleHooks on {asg_name!r} lists {hooks!r}, expected only {hook_name!r}"
    )
    hook = hooks[0]
    got_hook = {
        "LifecycleTransition": hook["LifecycleTransition"],
        "HeartbeatTimeout": hook["HeartbeatTimeout"],
        "DefaultResult": hook["DefaultResult"],
    }
    assert got_hook == {
        "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
        "HeartbeatTimeout": 60,
        "DefaultResult": "ABANDON",
    }, f"lifecycle hook {hook_name!r} reads {got_hook!r}"

    # ScheduledAction: the name is server-minted (not a template input), so find it by its other
    # templated properties in an independent, unfiltered list for the ASG, then check Ref and the
    # GetAtt ScheduledActionName both equal that independently-found name.
    actions = paginate(asgc, "describe_scheduled_actions", "ScheduledUpdateGroupActions",
                       AutoScalingGroupName=asg_name)
    assert len(actions) == 1, f"expected exactly one scheduled action on {asg_name!r}, got {actions!r}"
    action = actions[0]
    assert (out["ScheduledActionRef"], out["ScheduledActionNameAtt"]) == (
        action["ScheduledActionName"], action["ScheduledActionName"]
    ), (
        f"Ref {out['ScheduledActionRef']!r} / GetAtt {out['ScheduledActionNameAtt']!r} != "
        f"the independently-listed name {action['ScheduledActionName']!r}"
    )
    got_action = {
        "Recurrence": action["Recurrence"], "MinSize": action["MinSize"], "MaxSize": action["MaxSize"],
    }
    assert got_action == {"Recurrence": "0 0 1 1 *", "MinSize": 0, "MaxSize": 1}, (
        f"scheduled action reads {got_action!r}"
    )

    # WarmPool: its only identity is the ASG it belongs to (no Ref/GetAtt documented for this
    # type), so presence and every templated property are read back through DescribeWarmPool,
    # keyed by the ASG name the check created.
    pool = asgc.describe_warm_pool(AutoScalingGroupName=asg_name)["WarmPoolConfiguration"]
    assert pool is not None, f"expected a warm pool on {asg_name!r}, DescribeWarmPool returned none"
    got_pool = {
        "MinSize": pool.get("MinSize"), "MaxGroupPreparedCapacity": pool.get("MaxGroupPreparedCapacity"),
        "PoolState": pool.get("PoolState"),
    }
    assert got_pool == {"MinSize": 0, "MaxGroupPreparedCapacity": 0, "PoolState": "Stopped"}, (
        f"warm pool on {asg_name!r} reads {got_pool!r}"
    )

    # Child before parent: DescribeScheduledActions and DescribeWarmPool both refuse once their
    # ASG is gone, so each child's own delete is proven by a stack update that drops it while the
    # ASG still answers -- not by reading them again after the ASG itself is deleted.
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(subnet_id, asg_name, hook_name, False)
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"child-removing update ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    hooks_after = asgc.describe_lifecycle_hooks(
        AutoScalingGroupName=asg_name, LifecycleHookNames=[hook_name]
    )["LifecycleHooks"]
    assert hooks_after == [], f"lifecycle hook {hook_name!r} still exists after update: {hooks_after!r}"

    actions_after = paginate(asgc, "describe_scheduled_actions", "ScheduledUpdateGroupActions",
                             AutoScalingGroupName=asg_name)
    assert actions_after == [], (
        f"scheduled action(s) still exist on {asg_name!r} after update: {actions_after!r}"
    )

    pool_after = asgc.describe_warm_pool(AutoScalingGroupName=asg_name).get("WarmPoolConfiguration")
    assert pool_after is None, f"warm pool on {asg_name!r} still exists after update: {pool_after!r}"

    groups_still_up = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert [g["CreatedTime"] for g in groups_still_up] == [created], (
        f"expected the same {asg_name!r} to still exist while its children are proven gone, "
        f"got {groups_still_up!r}"
    )

    # Now the parent: delete the whole stack and prove the ASG itself is gone.
    delete_stack(cf, stack_id)
    groups_after = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert groups_after == [], f"ASG {asg_name!r} still exists after stack delete: {groups_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
