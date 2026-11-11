"""deploy-ivs-ad-configuration-mediatailor-playback-configuration-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ivs-ad-configuration-mediatailor-playback-configuration-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ivs", "mediatailor"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


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

_ADS_URL = "https://example.com/ads?duration=[session.avail_duration_secs]"


def _template(channel_name: str, playback_cfg_name: str, ad_cfg_name: str,
              insertion_mode: str) -> str:
    return json.dumps({
        "Resources": {
            "Channel": {"Type": "AWS::IVS::Channel",
                        "Properties": {"Name": channel_name, "Type": "BASIC"}},
            "PlaybackCfg": {"Type": "AWS::MediaTailor::PlaybackConfiguration", "Properties": {
                "Name": playback_cfg_name,
                "AdDecisionServerUrl": _ADS_URL,
                "VideoContentSourceUrl": {"Fn::Join": ["", [
                    "https://",
                    {"Fn::Select": [2, {"Fn::Split": [
                        "/", {"Fn::GetAtt": ["Channel", "PlaybackUrl"]}]}]},
                    "/",
                ]]},
                "InsertionMode": insertion_mode,
            }},
            "AdCfg": {"Type": "AWS::IVS::AdConfiguration", "Properties": {
                "Name": ad_cfg_name,
                "MediaTailorPlaybackConfigurations": [{"PlaybackConfigurationArn": {
                    "Fn::GetAtt": ["PlaybackCfg", "PlaybackConfigurationArn"]}}],
            }},
        },
        "Outputs": {
            "ChannelRef": {"Value": {"Ref": "Channel"}},
            "ChannelPlaybackUrl": {"Value": {"Fn::GetAtt": ["Channel", "PlaybackUrl"]}},
            "PlaybackRef": {"Value": {"Ref": "PlaybackCfg"}},
            "PlaybackArn": {"Value": {"Fn::GetAtt": ["PlaybackCfg", "PlaybackConfigurationArn"]}},
            "AdRef": {"Value": {"Ref": "AdCfg"}},
            "AdArn": {"Value": {"Fn::GetAtt": ["AdCfg", "Arn"]}},
        },
    })


def _ad_configs(ivs, name: str) -> list[str]:
    return [a["arn"] for a in paginate(ivs, "list_ad_configurations", "adConfigurations")
            if a["name"] == name]


def _masked_error(fn, account: str) -> tuple[str, str]:
    """(code, message with the account masked) of the ClientError ``fn()`` raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message", ""), account)
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IVS AdConfiguration linking a MediaTailor PlaybackConfiguration reads back at both.

    Each Ref and GetAtt matches its own service's listing, every templated property reads back
    (the content source is the channel's playback host), and the stack delete removes all three.
    """
    cfn = ctx.client("cloudformation")
    ivs = ctx.client("ivs")
    mediatailor = ctx.client("mediatailor")
    channel_name = ctx.unique_name("sim2real-behav-ivsadcfg-chan-")
    playback_cfg_name = ctx.unique_name("sim2real-behav-ivsadcfg-pbcfg-")
    ad_cfg_name = ctx.unique_name("sim2real-behav-ivsadcfg-ad-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-ivsadcfg-"),
                            _template(channel_name, playback_cfg_name, ad_cfg_name,
                                      "PLAYER_SELECT"))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    channels = [c["arn"] for c in paginate(ivs, "list_channels", "channels",
                                           filterByName=channel_name)
                if c["name"] == channel_name]
    assert channels == [out["ChannelRef"]], f"IVS lists channels {channels!r}"
    channel = ivs.get_channel(arn=channels[0])["channel"]
    got = (channel["name"], channel["type"], channel["playbackUrl"])
    assert got == (channel_name, "BASIC", out["ChannelPlaybackUrl"]), f"channel reads {got!r}"

    listed = [(p["Name"], p["PlaybackConfigurationArn"]) for p in paginate(
        mediatailor, "list_playback_configurations", "Items") if p["Name"] == playback_cfg_name]
    assert listed == [(out["PlaybackRef"], out["PlaybackArn"])], f"MediaTailor lists {listed!r}"
    playback_cfg = mediatailor.get_playback_configuration(Name=playback_cfg_name)
    got = (playback_cfg["InsertionMode"], playback_cfg["AdDecisionServerUrl"],
           playback_cfg["VideoContentSourceUrl"])
    want = ("PLAYER_SELECT", _ADS_URL, f"https://{channel['playbackUrl'].split('/')[2]}/")
    assert got == want, f"playback configuration reads {got!r}, expected {want!r}"

    ads = _ad_configs(ivs, ad_cfg_name)
    assert ads == [out["AdRef"]] == [out["AdArn"]], f"IVS lists ad configurations {ads!r}"
    ad_cfg = ivs.get_ad_configuration(arn=ads[0])["adConfiguration"]
    got = (ad_cfg["name"],
           [c["playbackConfigurationArn"] for c in ad_cfg["mediaTailorPlaybackConfigurations"]])
    assert got == (ad_cfg_name, [out["PlaybackArn"]]), f"ad configuration reads {got!r}"

    delete_stack(cfn, stack_id)
    for arn, getter in ((ads[0], ivs.get_ad_configuration), (channels[0], ivs.get_channel)):
        expect_error(lambda arn=arn, getter=getter: getter(arn=arn),
                     *("ResourceNotFoundException", f"Resource: {arn} not found"))
    got = _masked_error(lambda: mediatailor.get_playback_configuration(Name=playback_cfg_name),
                        ctx.account)
    want = ("NotFoundException",
            f"configuration {playback_cfg_name} not found for awsAccountId: <account>")
    assert got == want, f"after the delete GetPlaybackConfiguration raised {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
