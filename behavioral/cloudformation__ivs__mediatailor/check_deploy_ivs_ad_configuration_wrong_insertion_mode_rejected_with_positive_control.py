"""deploy-ivs-ad-configuration-wrong-insertion-mode-rejected-with-positive-control."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ivs-ad-configuration-wrong-insertion-mode-rejected-with-positive-control"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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


def _rejected(playback_cfg_name: str) -> tuple[str, str]:
    return (
        f"Request member: insertionMode for playback configuration '{playback_cfg_name}' "
        "failed to satisfy the constraints: invalid insertion mode provided for the provided "
        "playback configuration in media_tailor_playback_configurations, insertion mode must be "
        "set to 'PLAYER_SELECT' for use with ad configurations (Service: ivs; Operation: "
        "CreateAdConfiguration; Status Code: 400; Error Code: ValidationException; Request ID: "
        "<id>)",
        "InvalidRequest",
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IVS AdConfiguration on a STITCHED_ONLY MediaTailor playback configuration is refused.

    The stack rolls back with IVS's reason and neither the ad configuration nor the playback
    configuration remains, while the same template with PLAYER_SELECT deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    ivs = ctx.client("ivs")
    mediatailor = ctx.client("mediatailor")
    good = tuple(ctx.unique_name(f"sim2real-behav-ivsadgood-{p}-") for p in ("chan", "pbcfg", "ad"))
    bad = tuple(ctx.unique_name(f"sim2real-behav-ivsadbad-{p}-") for p in ("chan", "pbcfg", "ad"))

    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-ivsadgood-"),
                           _template(*good, "PLAYER_SELECT"))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-ivsadbad-"),
                          _template(*bad, "STITCHED_ONLY"))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "AdCfg")
    got = handler_reason(reason, ctx.account)
    assert got == _rejected(bad[1]), f"handler reason {got!r}, expected {_rejected(bad[1])!r}"

    # Rollback absence at both services, by the names the rejected stack used.
    assert _ad_configs(ivs, bad[2]) == [], "IVS lists the rejected ad configuration"
    got = _masked_error(lambda: mediatailor.get_playback_configuration(Name=bad[1]), ctx.account)
    want = ("NotFoundException", f"configuration {bad[1]} not found for awsAccountId: <account>")
    assert got == want, f"the rolled-back playback configuration reads {got!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    playback_cfg = mediatailor.get_playback_configuration(Name=good[1])
    got = (playback_cfg["PlaybackConfigurationArn"], playback_cfg["InsertionMode"])
    assert got == (out["PlaybackArn"], "PLAYER_SELECT"), f"control playback configuration {got!r}"
    ads = _ad_configs(ivs, good[2])
    assert ads == [out["AdArn"]], f"IVS lists {ads!r} for the control"
    ad_cfg = ivs.get_ad_configuration(arn=ads[0])["adConfiguration"]
    linked = [c["playbackConfigurationArn"] for c in ad_cfg["mediaTailorPlaybackConfigurations"]]
    assert linked == [out["PlaybackArn"]], f"the control ad configuration links {linked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
