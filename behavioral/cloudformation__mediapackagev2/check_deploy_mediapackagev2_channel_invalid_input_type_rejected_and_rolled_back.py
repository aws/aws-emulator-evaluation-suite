"""deploy-mediapackagev2-channel-invalid-input-type-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mediapackagev2-channel-invalid-input-type-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "mediapackagev2"]

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


_CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)


_CHANNEL_GROUP_GONE = ("ResourceNotFoundException", _CHANNEL_GROUP_NOT_FOUND)
_REJECTED = [(
    "Channel", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "NOT_A_REAL_INPUT_TYPE is not a valid enum value. Supported values: [HLS, CMAF, MULTIVIEW]",
    "/Resources/Channel/Properties/InputType",
)]


def _template(group: str, channel: str, input_type: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ChannelGroup": {
                "Type": "AWS::MediaPackageV2::ChannelGroup",
                "Properties": {"ChannelGroupName": group},
            },
            "Channel": {
                "Type": "AWS::MediaPackageV2::Channel",
                "Properties": {
                    "ChannelGroupName": group, "ChannelName": channel, "InputType": input_type,
                },
                "DependsOn": "ChannelGroup",
            },
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::MediaPackageV2::Channel with an InputType outside HLS/CMAF/MULTIVIEW
    is refused by early validation at its exact path and neither the channel nor its group
    exists, while the same template with a valid InputType deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediapackagev2-channel.html
    """
    cfn = ctx.client("cloudformation")
    mp = ctx.client("mediapackagev2")

    bad_stack_name = ctx.unique_name("sim2real-mpv2badch-")
    bad_group = ctx.unique_name("sim2real-mpv2cg-")
    bad_channel = ctx.unique_name("sim2real-mpv2ch-")

    bad_stack_id = create_stack(ctx, cfn, bad_stack_name,
                                _template(bad_group, bad_channel, "NOT_A_REAL_INPUT_TYPE"))
    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    # Early validation refuses the enum before any handler runs: the VALIDATION_ERROR row is the
    # one place the rejected property and its reason appear.
    rows = [r for r in validation_rows(cfn, bad_stack_id) if r[3] == "FAIL"]
    assert rows == _REJECTED, f"VALIDATION_ERROR rows {rows!r}, expected {_REJECTED!r}"

    # Neither resource exists at MediaPackage v2, asserted before this check deletes anything.
    # GetChannel checks the channel group first, so with both absent it names the group.
    expect_error(lambda: mp.get_channel(ChannelGroupName=bad_group, ChannelName=bad_channel),
                 *_CHANNEL_GROUP_GONE)
    expect_error(lambda: mp.get_channel_group(ChannelGroupName=bad_group), *_CHANNEL_GROUP_GONE)

    # Positive control: the same template, InputType given a valid value, deploys and reads back.
    good_stack_name = ctx.unique_name("sim2real-mpv2goodch-")
    good_group = ctx.unique_name("sim2real-mpv2cg-")
    good_channel = ctx.unique_name("sim2real-mpv2ch-")
    good_stack_id = create_stack(ctx, cfn, good_stack_name,
                                 _template(good_group, good_channel, "HLS"))
    status = wait_stack(cfn, good_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_stack_id))!r}"
    )
    listed = [c for c in paginate(mp, "list_channels", "Items", ChannelGroupName=good_group)
              if c["ChannelName"] == good_channel]
    assert len(listed) == 1, f"ListChannels lists {len(listed)} named {good_channel!r}"
    control = mp.get_channel(ChannelGroupName=good_group, ChannelName=good_channel)
    got = (control["ChannelGroupName"], control["ChannelName"], control["InputType"])
    assert got == (good_group, good_channel, "HLS"), f"control channel reads {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
