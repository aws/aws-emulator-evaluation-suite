"""deploy-mediatailor-source-location-live-source-vod-source-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mediatailor-source-location-live-source-vod-source-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "mediatailor"]

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


_BASE_URL = "https://example.com"
_VOD = [{"Path": "/vod/index", "SourceGroup": "sg1", "Type": "HLS"}]
_LIVE = [{"Path": "/live/index", "SourceGroup": "sg1", "Type": "HLS"}]
_LOCATION_GONE = ("NotFoundException", "The specified source-location doesn't exist.")


def _template(sl_name, vs_name, ls_name, with_sources=True):
    resources = {
        "SourceLocation": {
            "Type": "AWS::MediaTailor::SourceLocation",
            "Properties": {
                "SourceLocationName": sl_name,
                "HttpConfiguration": {"BaseUrl": _BASE_URL},
                "Tags": [{"Key": "sim2real-sl", "Value": sl_name}],
            },
        },
    }
    outputs = {
        "SourceLocationRef": {"Value": {"Ref": "SourceLocation"}},
        "SourceLocationArn": {"Value": {"Fn::GetAtt": ["SourceLocation", "Arn"]}},
    }
    if with_sources:
        resources["VodSource"] = {
            "Type": "AWS::MediaTailor::VodSource",
            "Properties": {
                "SourceLocationName": {"Ref": "SourceLocation"},
                "VodSourceName": vs_name,
                "HttpPackageConfigurations": _VOD,
                "Tags": [{"Key": "sim2real-vs", "Value": vs_name}],
            },
        }
        resources["LiveSource"] = {
            "Type": "AWS::MediaTailor::LiveSource",
            "Properties": {
                "SourceLocationName": {"Ref": "SourceLocation"},
                "LiveSourceName": ls_name,
                "HttpPackageConfigurations": _LIVE,
                "Tags": [{"Key": "sim2real-ls", "Value": ls_name}],
            },
        }
        outputs.update({
            "VodSourceRef": {"Value": {"Ref": "VodSource"}},
            "VodSourceArn": {"Value": {"Fn::GetAtt": ["VodSource", "Arn"]}},
            "LiveSourceRef": {"Value": {"Ref": "LiveSource"}},
            "LiveSourceArn": {"Value": {"Fn::GetAtt": ["LiveSource", "Arn"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SourceLocation, LiveSource and VodSource read back through MediaTailor with
    the template's base URL, package configurations and tags; an update dropping both sources
    empties their lists while the location answers, and the stack delete removes the location.
    """
    cfn = ctx.client("cloudformation")
    mt = ctx.client("mediatailor")
    stack_name = ctx.unique_name("sim2real-behav-cfn-mtsrc-")
    sl_name = ctx.unique_name("sim2real-behav-sl-")
    vs_name = ctx.unique_name("sim2real-behav-vs-")
    ls_name = ctx.unique_name("sim2real-behav-ls-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(sl_name, vs_name, ls_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Each Ref and GetAtt Arn against its independent list entry; every templated property.
    locations = [s for s in paginate(mt, "list_source_locations", "Items")
                 if s["SourceLocationName"] == sl_name]
    got = [(s["SourceLocationName"], s["Arn"], s["HttpConfiguration"]) for s in locations]
    assert got == [(outputs["SourceLocationRef"], outputs["SourceLocationArn"],
                    {"BaseUrl": _BASE_URL})], f"ListSourceLocations entries {got!r}"
    vods = [v for v in paginate(mt, "list_vod_sources", "Items", SourceLocationName=sl_name)
            if v["VodSourceName"] == vs_name]
    got = [(v["Arn"], v["HttpPackageConfigurations"]) for v in vods]
    assert got == [(outputs["VodSourceArn"], _VOD)], f"ListVodSources entries {got!r}"
    assert outputs["VodSourceRef"] == f"{sl_name}|{vs_name}", f"Ref {outputs['VodSourceRef']!r}"
    lives = [v for v in paginate(mt, "list_live_sources", "Items", SourceLocationName=sl_name)
             if v["LiveSourceName"] == ls_name]
    got = [(v["Arn"], v["HttpPackageConfigurations"]) for v in lives]
    assert got == [(outputs["LiveSourceArn"], _LIVE)], f"ListLiveSources entries {got!r}"
    assert outputs["LiveSourceRef"] == f"{ls_name}|{sl_name}", f"Ref {outputs['LiveSourceRef']!r}"

    # Template tags plus the propagated stack tag, CloudFormation's aws:* tags dropped.
    for arn, key, value in ((locations[0]["Arn"], "sim2real-sl", sl_name),
                            (vods[0]["Arn"], "sim2real-vs", vs_name),
                            (lives[0]["Arn"], "sim2real-ls", ls_name)):
        got_tags = {k: v for k, v in mt.list_tags_for_resource(ResourceArn=arn)["Tags"].items()
                    if not k.startswith("aws:")}
        assert got_tags == {"sim2real": stack_name, key: value}, f"tags of {arn!r}: {got_tags!r}"

    # Children first: an update dropping both sources empties both lists while the location
    # still answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(sl_name, vs_name, ls_name, with_sources=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"source-removing update ended {status!r}"
    left = (paginate(mt, "list_vod_sources", "Items", SourceLocationName=sl_name),
            paginate(mt, "list_live_sources", "Items", SourceLocationName=sl_name))
    assert left == ([], []), f"(vod, live) sources still listed after the update: {left!r}"
    sl_arn = mt.describe_source_location(SourceLocationName=sl_name)["Arn"]
    assert sl_arn == locations[0]["Arn"], f"source location reads {sl_arn!r} after the update"

    delete_stack(cfn, stack_id)
    expect_error(lambda: mt.describe_source_location(SourceLocationName=sl_name), *_LOCATION_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
