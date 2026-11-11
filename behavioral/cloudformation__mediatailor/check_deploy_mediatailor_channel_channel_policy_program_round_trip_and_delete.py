"""deploy-mediatailor-channel-channel-policy-program-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mediatailor-channel-channel-policy-program-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "mediatailor"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_SOURCE_GROUP = "sg1"
_PACKAGE = [{"Path": "/vod/index", "SourceGroup": _SOURCE_GROUP, "Type": "HLS"}]
_CHANNEL_GONE = ("NotFoundException", "The specified channel doesn't exist.")


def _policy_doc(principal, resource):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowGetManifest",
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": "mediatailor:GetManifest",
            "Resource": resource,
        }],
    }


def _template(sl_name, vs_name, ch_name, pg_name, with_children=True):
    resources = {
        "SourceLocation": {
            "Type": "AWS::MediaTailor::SourceLocation",
            "Properties": {
                "SourceLocationName": sl_name,
                "HttpConfiguration": {"BaseUrl": "https://example.com"},
                "Tags": [{"Key": "sim2real-sl", "Value": sl_name}],
            },
        },
        "Channel": {
            "Type": "AWS::MediaTailor::Channel",
            "Properties": {
                "ChannelName": ch_name,
                "PlaybackMode": "LOOP",
                "Outputs": [{
                    "ManifestName": "index",
                    "SourceGroup": _SOURCE_GROUP,
                    "HlsPlaylistSettings": {"ManifestWindowSeconds": 30},
                }],
                "Tags": [{"Key": "sim2real-ch", "Value": ch_name}],
            },
        },
    }
    outputs = {
        "ChannelRef": {"Value": {"Ref": "Channel"}},
        "ChannelArn": {"Value": {"Fn::GetAtt": ["Channel", "Arn"]}},
    }
    if with_children:
        resources["VodSource"] = {
            "Type": "AWS::MediaTailor::VodSource",
            "Properties": {
                "SourceLocationName": {"Ref": "SourceLocation"},
                "VodSourceName": vs_name,
                "HttpPackageConfigurations": _PACKAGE,
                "Tags": [{"Key": "sim2real-vs", "Value": vs_name}],
            },
        }
        resources["ChannelPolicy"] = {
            "Type": "AWS::MediaTailor::ChannelPolicy",
            "Properties": {
                "ChannelName": {"Ref": "Channel"},
                "Policy": _policy_doc(
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"},
                    {"Fn::GetAtt": ["Channel", "Arn"]},
                ),
            },
        }
        resources["Program"] = {
            "Type": "AWS::MediaTailor::Program",
            "DependsOn": ["VodSource"],
            "Properties": {
                "ChannelName": {"Ref": "Channel"},
                "ProgramName": pg_name,
                "SourceLocationName": {"Ref": "SourceLocation"},
                "VodSourceName": vs_name,
                "ScheduleConfiguration": {
                    "Transition": {"Type": "RELATIVE", "RelativePosition": "AFTER_PROGRAM"},
                },
            },
        }
        outputs.update({
            "ChannelPolicyRef": {"Value": {"Ref": "ChannelPolicy"}},
            "ProgramRef": {"Value": {"Ref": "Program"}},
            "ProgramArn": {"Value": {"Fn::GetAtt": ["Program", "Arn"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _programs(mt, ch_name):
    """Distinct ``(ProgramName, Arn)`` of the schedule's program entries in the next hour.

    One page only: AWS refused this LOOP channel's schedule NextToken on the next request
    ("The pagination token isn't valid."), so the read is one bounded window (60 minutes, up
    to 100 entries) in which the channel's single program loops. Filler entries carry no
    ProgramName.
    """
    page = mt.get_channel_schedule(ChannelName=ch_name, DurationMinutes="60", MaxResults=100)
    return sorted({(e["ProgramName"], e["Arn"]) for e in page["Items"] if e.get("ProgramName")})


def _own_tags(mt, arn):
    """A resource's tags without CloudFormation's aws:* system tags."""
    return {k: v for k, v in mt.list_tags_for_resource(ResourceArn=arn)["Tags"].items()
            if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Channel, ChannelPolicy, Program and their VodSource read back through
    MediaTailor with the template's values and tags; an update dropping the program and VodSource
    empties the schedule and source list while the parents answer, and the stack delete ends it.
    """
    cfn = ctx.client("cloudformation")
    mt = ctx.client("mediatailor")
    stack = ctx.unique_name("sim2real-behav-cfn-mtch-")
    sl_name = ctx.unique_name("sim2real-behav-sl-")
    vs_name = ctx.unique_name("sim2real-behav-vs-")
    ch_name = ctx.unique_name("sim2real-behav-ch-")
    pg_name = ctx.unique_name("sim2real-behav-pg-")

    stack_id = create_stack(ctx, cfn, stack, _template(sl_name, vs_name, ch_name, pg_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # Channel: Ref and GetAtt Arn against the independent ListChannels entry.
    channels = [c for c in paginate(mt, "list_channels", "Items") if c["ChannelName"] == ch_name]
    assert [(c["ChannelName"], c["Arn"]) for c in channels] == [
        (out["ChannelRef"], out["ChannelArn"])
    ], f"ListChannels entries named {ch_name!r}: {channels!r}"
    channel = mt.describe_channel(ChannelName=ch_name)
    got = (channel["PlaybackMode"],
           [(o["ManifestName"], o["SourceGroup"], o["HlsPlaylistSettings"]["ManifestWindowSeconds"])
            for o in channel["Outputs"]])
    assert got == ("LOOP", [("index", _SOURCE_GROUP, 30)]), f"channel reads {got!r}"

    # ChannelPolicy: Ref is the channel name; the stored document is the template's.
    assert out["ChannelPolicyRef"] == ch_name, f"Ref ChannelPolicy {out['ChannelPolicyRef']!r}"
    root = f"arn:{partition}:iam::{ctx.account}:root"
    read_policy = json.loads(mt.get_channel_policy(ChannelName=ch_name)["Policy"])
    assert read_policy == _policy_doc(root, channel["Arn"]), f"channel policy {read_policy!r}"

    # Program: Ref and GetAtt == the ARN the channel's schedule lists under the declared name.
    listed = _programs(mt, ch_name)
    assert listed == [(pg_name, out["ProgramRef"])], f"channel schedule {listed!r}"
    assert out["ProgramArn"] == out["ProgramRef"], f"GetAtt Program.Arn {out['ProgramArn']!r}"
    program = mt.describe_program(ChannelName=ch_name, ProgramName=pg_name)
    got = (program["Arn"], program["SourceLocationName"], program["VodSourceName"])
    assert got == (out["ProgramRef"], sl_name, vs_name), f"program reads {got!r}"

    # SourceLocation and VodSource: listed by name, every templated property read back.
    locations = [s for s in paginate(mt, "list_source_locations", "Items")
                 if s["SourceLocationName"] == sl_name]
    assert [s["HttpConfiguration"] for s in locations] == [{"BaseUrl": "https://example.com"}], (
        f"ListSourceLocations entries named {sl_name!r}: {locations!r}"
    )
    vod_sources = [v for v in paginate(mt, "list_vod_sources", "Items", SourceLocationName=sl_name)
                   if v["VodSourceName"] == vs_name]
    assert [v["HttpPackageConfigurations"] for v in vod_sources] == [_PACKAGE], (
        f"ListVodSources entries named {vs_name!r}: {vod_sources!r}"
    )

    # Template tags plus the propagated stack tag, CloudFormation's aws:* tags dropped.
    for arn, key, value in ((locations[0]["Arn"], "sim2real-sl", sl_name),
                            (vod_sources[0]["Arn"], "sim2real-vs", vs_name),
                            (channel["Arn"], "sim2real-ch", ch_name)):
        got_tags = _own_tags(mt, arn)
        assert got_tags == {"sim2real": stack, key: value}, f"tags of {arn!r}: {got_tags!r}"

    # Children first: an update dropping the program, policy and VodSource empties the channel's
    # schedule and the location's source list while the channel and the location still answer.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(sl_name, vs_name, ch_name, pg_name,
                                            with_children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    assert _programs(mt, ch_name) == [], (
        "the program is still on the channel's schedule after the update"
    )
    assert paginate(mt, "list_vod_sources", "Items", SourceLocationName=sl_name) == [], (
        "the VodSource is still listed after the update"
    )
    ch_arn = mt.describe_channel(ChannelName=ch_name)["Arn"]
    assert ch_arn == channel["Arn"], f"channel Arn after the update {ch_arn!r} != {channel['Arn']!r}"
    sl_arn = mt.describe_source_location(SourceLocationName=sl_name)["Arn"]
    assert sl_arn == locations[0]["Arn"], (
        f"source location Arn after the update {sl_arn!r} != {locations[0]['Arn']!r}"
    )

    delete_stack(cfn, stack_id)
    expect_error(lambda: mt.describe_channel(ChannelName=ch_name), *_CHANNEL_GONE)
    expect_error(lambda: mt.get_channel_policy(ChannelName=ch_name), *_CHANNEL_GONE)
    remaining = [s for s in paginate(mt, "list_source_locations", "Items")
                 if s["SourceLocationName"] == sl_name]
    assert remaining == [], f"source location {sl_name!r} is still listed after the stack delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
