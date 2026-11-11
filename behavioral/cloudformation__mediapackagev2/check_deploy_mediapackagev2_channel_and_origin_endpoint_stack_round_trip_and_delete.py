"""deploy-mediapackagev2-channel-and-origin-endpoint-stack-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mediapackagev2-channel-and-origin-endpoint-stack-round-trip-and-delete"
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


_CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)
_ORIGIN_ENDPOINT_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your origin endpoint. "
    "Verify your origin endpoint name or add an origin endpoint and then try again"
)
_POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)

_CHANNEL_GROUP_GONE = ("ResourceNotFoundException", _CHANNEL_GROUP_NOT_FOUND)
_ORIGIN_ENDPOINT_GONE = ("ResourceNotFoundException", _ORIGIN_ENDPOINT_NOT_FOUND)
_POLICY_GONE = ("ResourceNotFoundException", _POLICY_NOT_FOUND)


def _channel_policy_doc(principal, channel_arn) -> dict:
    return {
        "Version": "2012-10-17",
        "Id": "Sim2realChannelIngestPolicy",
        "Statement": [{
            "Sid": "AllowAccountIngest",
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": "mediapackagev2:PutObject",
            "Resource": channel_arn,
        }],
    }


def _origin_endpoint_policy_doc(principal, endpoint_arn) -> dict:
    return {
        "Version": "2012-10-17",
        "Id": "Sim2realOriginEndpointReadPolicy",
        "Statement": [{
            "Sid": "AllowAccountRead",
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": "mediapackagev2:GetObject",
            "Resource": endpoint_arn,
        }],
    }


_ROOT = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}


def _tags(key, value):
    return [{"Key": key, "Value": value}]


def _full_template(group: str, channel: str, endpoint: str,
                    group_desc: str, channel_desc: str, endpoint_desc: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ChannelGroup": {
                "Type": "AWS::MediaPackageV2::ChannelGroup",
                "Properties": {"ChannelGroupName": group, "Description": group_desc,
                               "Tags": _tags("sim2real-cg", group)},
            },
            "Channel": {
                "Type": "AWS::MediaPackageV2::Channel",
                "Properties": {
                    "ChannelGroupName": group, "ChannelName": channel,
                    "InputType": "HLS", "Description": channel_desc,
                    "Tags": _tags("sim2real-ch", channel),
                },
                "DependsOn": "ChannelGroup",
            },
            "ChannelPolicy": {
                "Type": "AWS::MediaPackageV2::ChannelPolicy",
                "Properties": {
                    "ChannelGroupName": group, "ChannelName": channel,
                    "Policy": _channel_policy_doc(_ROOT, {"Fn::GetAtt": ["Channel", "Arn"]}),
                },
            },
            "OriginEndpoint": {
                "Type": "AWS::MediaPackageV2::OriginEndpoint",
                "Properties": {
                    "ChannelGroupName": group, "ChannelName": channel,
                    "OriginEndpointName": endpoint, "ContainerType": "TS",
                    "Description": endpoint_desc,
                    "HlsManifests": [{"ManifestName": "index"}],
                    "Tags": _tags("sim2real-oe", endpoint),
                },
                "DependsOn": "Channel",
            },
            "OriginEndpointPolicy": {
                "Type": "AWS::MediaPackageV2::OriginEndpointPolicy",
                "Properties": {
                    "ChannelGroupName": group, "ChannelName": channel,
                    "OriginEndpointName": endpoint,
                    "Policy": _origin_endpoint_policy_doc(
                        _ROOT, {"Fn::GetAtt": ["OriginEndpoint", "Arn"]}
                    ),
                },
            },
        },
        "Outputs": {
            "ChannelGroupArn": {"Value": {"Ref": "ChannelGroup"}},
            "ChannelGroupCreatedAt": {"Value": {"Fn::GetAtt": ["ChannelGroup", "CreatedAt"]}},
            "ChannelGroupEgressDomain": {"Value": {"Fn::GetAtt": ["ChannelGroup", "EgressDomain"]}},
            "ChannelArn": {"Value": {"Ref": "Channel"}},
            "ChannelCreatedAt": {"Value": {"Fn::GetAtt": ["Channel", "CreatedAt"]}},
            "ChannelPolicyRef": {"Value": {"Ref": "ChannelPolicy"}},
            "OriginEndpointArn": {"Value": {"Ref": "OriginEndpoint"}},
            "OriginEndpointCreatedAt": {"Value": {"Fn::GetAtt": ["OriginEndpoint", "CreatedAt"]}},
            "OriginEndpointPolicyRef": {"Value": {"Ref": "OriginEndpointPolicy"}},
        },
    })


def _reduced_template(group: str, channel: str, group_desc: str, channel_desc: str) -> str:
    """Only the ChannelGroup and Channel: an update that removes the three child resources."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ChannelGroup": {
                "Type": "AWS::MediaPackageV2::ChannelGroup",
                "Properties": {"ChannelGroupName": group, "Description": group_desc,
                               "Tags": _tags("sim2real-cg", group)},
            },
            "Channel": {
                "Type": "AWS::MediaPackageV2::Channel",
                "Properties": {
                    "ChannelGroupName": group, "ChannelName": channel,
                    "InputType": "HLS", "Description": channel_desc,
                    "Tags": _tags("sim2real-ch", channel),
                },
                "DependsOn": "ChannelGroup",
            },
        },
        "Outputs": {
            "ChannelGroupArn": {"Value": {"Ref": "ChannelGroup"}},
            "ChannelArn": {"Value": {"Ref": "Channel"}},
        },
    })


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ChannelGroup, Channel, ChannelPolicy, OriginEndpoint and
    OriginEndpointPolicy are real at MediaPackage v2: Ref and GetAtt match the service's own
    value, and each is gone there once the update or delete that removes it completes.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediapackagev2-channel.html
    """
    cfn = ctx.client("cloudformation")
    mp = ctx.client("mediapackagev2")
    region = ctx.region

    stack_name = ctx.unique_name("sim2real-mpv2stack-")
    group = ctx.unique_name("sim2real-mpv2cg-")
    channel = ctx.unique_name("sim2real-mpv2ch-")
    endpoint = ctx.unique_name("sim2real-mpv2oe-")
    group_desc = ctx.unique_name("sim2real-desc-cg-")
    channel_desc = ctx.unique_name("sim2real-desc-ch-")
    endpoint_desc = ctx.unique_name("sim2real-desc-oe-")

    stack_id = create_stack(ctx, cfn, stack_name, _full_template(
        group, channel, endpoint, group_desc, channel_desc, endpoint_desc
    ))
    created = wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"stack ended {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    account = ctx.account
    root = f"arn:{partition}:iam::{account}:root"

    # ---- ChannelGroup: Ref is the documented ARN form; GetAtt and the declared Description
    # read back exactly what GetChannelGroup reports.
    cg = mp.get_channel_group(ChannelGroupName=group)
    expected_cg_arn = f"arn:{partition}:mediapackagev2:{region}:{account}:channelGroup/{group}"
    assert outputs["ChannelGroupArn"] == expected_cg_arn, (
        f"Ref ChannelGroup was {outputs['ChannelGroupArn']!r}, expected {expected_cg_arn!r}"
    )
    assert cg["Arn"] == outputs["ChannelGroupArn"], (
        f"GetChannelGroup Arn {cg['Arn']!r} does not match the stack's Ref {outputs['ChannelGroupArn']!r}"
    )
    assert _parse_iso(outputs["ChannelGroupCreatedAt"]) == cg["CreatedAt"], (
        f"GetAtt CreatedAt {outputs['ChannelGroupCreatedAt']!r} does not match "
        f"GetChannelGroup's {cg['CreatedAt']!r}"
    )
    assert outputs["ChannelGroupEgressDomain"] == cg["EgressDomain"], (
        f"GetAtt EgressDomain {outputs['ChannelGroupEgressDomain']!r} does not match "
        f"GetChannelGroup's {cg['EgressDomain']!r}"
    )
    assert cg["Description"] == group_desc, (
        f"expected the declared Description {group_desc!r}, GetChannelGroup reports {cg['Description']!r}"
    )

    # ---- Channel: same shape, plus the declared InputType.
    ch = mp.get_channel(ChannelGroupName=group, ChannelName=channel)
    expected_ch_arn = f"arn:{partition}:mediapackagev2:{region}:{account}:channelGroup/{group}/channel/{channel}"
    assert outputs["ChannelArn"] == expected_ch_arn, (
        f"Ref Channel was {outputs['ChannelArn']!r}, expected {expected_ch_arn!r}"
    )
    assert ch["Arn"] == outputs["ChannelArn"], (
        f"GetChannel Arn {ch['Arn']!r} does not match the stack's Ref {outputs['ChannelArn']!r}"
    )
    assert _parse_iso(outputs["ChannelCreatedAt"]) == ch["CreatedAt"], (
        f"GetAtt CreatedAt {outputs['ChannelCreatedAt']!r} does not match GetChannel's {ch['CreatedAt']!r}"
    )
    assert ch["InputType"] == "HLS", f"expected InputType 'HLS', GetChannel reports {ch['InputType']!r}"
    assert ch["Description"] == channel_desc, (
        f"expected the declared Description {channel_desc!r}, GetChannel reports {ch['Description']!r}"
    )

    # ---- ChannelPolicy: Ref is "ChannelGroupName/ChannelName"; the policy document echoes the
    # template's statement with the Channel's own (now-known) Arn.
    cp = mp.get_channel_policy(ChannelGroupName=group, ChannelName=channel)
    expected_cp_ref = f"{group}|{channel}"
    assert outputs["ChannelPolicyRef"] == expected_cp_ref, (
        f"Ref ChannelPolicy was {outputs['ChannelPolicyRef']!r}, expected {expected_cp_ref!r}"
    )
    expected_cp_doc = _channel_policy_doc(root, ch["Arn"])
    fetched_cp_doc = json.loads(cp["Policy"])
    assert fetched_cp_doc == expected_cp_doc, (
        f"expected the declared ChannelPolicy document {expected_cp_doc!r}, got {fetched_cp_doc!r}"
    )

    # ---- OriginEndpoint: same ARN/GetAtt/property shape as Channel, plus the declared manifest.
    oe = mp.get_origin_endpoint(ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint)
    expected_oe_arn = (
        f"arn:{partition}:mediapackagev2:{region}:{account}:channelGroup/{group}/channel/{channel}"
        f"/originEndpoint/{endpoint}"
    )
    assert outputs["OriginEndpointArn"] == expected_oe_arn, (
        f"Ref OriginEndpoint was {outputs['OriginEndpointArn']!r}, expected {expected_oe_arn!r}"
    )
    assert oe["Arn"] == outputs["OriginEndpointArn"], (
        f"GetOriginEndpoint Arn {oe['Arn']!r} does not match the stack's Ref {outputs['OriginEndpointArn']!r}"
    )
    assert _parse_iso(outputs["OriginEndpointCreatedAt"]) == oe["CreatedAt"], (
        f"GetAtt CreatedAt {outputs['OriginEndpointCreatedAt']!r} does not match "
        f"GetOriginEndpoint's {oe['CreatedAt']!r}"
    )
    assert oe["ContainerType"] == "TS", (
        f"expected ContainerType 'TS', GetOriginEndpoint reports {oe['ContainerType']!r}"
    )
    assert oe["Description"] == endpoint_desc, (
        f"expected the declared Description {endpoint_desc!r}, GetOriginEndpoint reports "
        f"{oe['Description']!r}"
    )
    manifest_names = [m["ManifestName"] for m in oe["HlsManifests"]]
    assert manifest_names == ["index"], (
        f"expected the declared HlsManifests ['index'], GetOriginEndpoint reports {manifest_names!r}"
    )

    # ---- OriginEndpointPolicy: Ref is "ChannelGroupName/ChannelName/OriginEndpointName".
    oep = mp.get_origin_endpoint_policy(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )
    expected_oep_ref = f"{group}|{channel}|{endpoint}"
    assert outputs["OriginEndpointPolicyRef"] == expected_oep_ref, (
        f"Ref OriginEndpointPolicy was {outputs['OriginEndpointPolicyRef']!r}, expected "
        f"{expected_oep_ref!r}"
    )
    expected_oep_doc = _origin_endpoint_policy_doc(root, oe["Arn"])
    fetched_oep_doc = json.loads(oep["Policy"])
    assert fetched_oep_doc == expected_oep_doc, (
        f"expected the declared OriginEndpointPolicy document {expected_oep_doc!r}, got "
        f"{fetched_oep_doc!r}"
    )

    # ---- Template tags plus the propagated stack tag, CloudFormation's aws:* tags dropped.
    for arn, key, value in ((cg["Arn"], "sim2real-cg", group), (ch["Arn"], "sim2real-ch", channel),
                            (oe["Arn"], "sim2real-oe", endpoint)):
        got_tags = {k: v for k, v in mp.list_tags_for_resource(ResourceArn=arn)["Tags"].items()
                    if not k.startswith("aws:")}
        assert got_tags == {"sim2real": stack_name, key: value}, f"tags of {arn!r}: {got_tags!r}"

    # ---- Remove the three child resources by update; each must be gone at MediaPackage v2
    # while the parent Channel and ChannelGroup stay the SAME resource (identical Arn + CreatedAt).
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_reduced_template(group, channel, group_desc, channel_desc)
    )
    updated = wait_stack(cfn, stack_id)
    assert updated == "UPDATE_COMPLETE", f"update ended {updated!r}, expected UPDATE_COMPLETE"

    expect_error(lambda: mp.get_channel_policy(ChannelGroupName=group, ChannelName=channel),
                 *_POLICY_GONE)

    expect_error(lambda: mp.get_origin_endpoint(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint,
    ), *_ORIGIN_ENDPOINT_GONE)

    # GetOriginEndpointPolicy checks the origin endpoint's own existence before its policy's, so
    # once the endpoint is gone the message names the endpoint, not the policy.
    expect_error(lambda: mp.get_origin_endpoint_policy(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint,
    ), *_ORIGIN_ENDPOINT_GONE)

    ch_after_update = mp.get_channel(ChannelGroupName=group, ChannelName=channel)
    assert ch_after_update["Arn"] == ch["Arn"] and ch_after_update["CreatedAt"] == ch["CreatedAt"], (
        f"the channel's own identity changed across the update: before {ch['Arn']!r}/{ch['CreatedAt']!r}, "
        f"after {ch_after_update['Arn']!r}/{ch_after_update['CreatedAt']!r}"
    )
    cg_after_update = mp.get_channel_group(ChannelGroupName=group)
    assert cg_after_update["Arn"] == cg["Arn"] and cg_after_update["CreatedAt"] == cg["CreatedAt"], (
        f"the channel group's own identity changed across the update: before "
        f"{cg['Arn']!r}/{cg['CreatedAt']!r}, after {cg_after_update['Arn']!r}/{cg_after_update['CreatedAt']!r}"
    )

    # ---- Delete the whole stack; the parent Channel and ChannelGroup are now gone too.
    delete_stack(cfn, stack_id)

    # GetChannel checks the channel group's own existence before the channel's, so once the
    # group is also gone the message names the group, not the channel.
    expect_error(lambda: mp.get_channel(ChannelGroupName=group, ChannelName=channel),
                 *_CHANNEL_GROUP_GONE)

    expect_error(lambda: mp.get_channel_group(ChannelGroupName=group), *_CHANNEL_GROUP_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
