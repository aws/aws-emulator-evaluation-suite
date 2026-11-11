"""deploy-mediaconvert-queue-jobtemplate-preset-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mediaconvert-queue-jobtemplate-preset-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "mediaconvert"]

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

_GONE = ("NotFoundException", "The resource you specified in name was not found.")
_H264_SETTINGS = {
    "ContainerSettings": {"Container": "MP4"},
    "VideoDescription": {
        "CodecSettings": {
            "Codec": "H_264",
            "H264Settings": {"RateControlMode": "CBR", "Bitrate": 1000000},
        }
    },
}


def _job_template_settings(destination: str) -> dict:
    return {
        "OutputGroups": [
            {
                "Name": "File Group",
                "OutputGroupSettings": {
                    "Type": "FILE_GROUP_SETTINGS",
                    "FileGroupSettings": {"Destination": destination},
                },
                "Outputs": [_H264_SETTINGS],
            }
        ]
    }


def _template(names: tuple[str, str, str], destination: str, queue_status: str) -> str:
    queue_name, jt_name, preset_name = names
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::MediaConvert::Queue",
                "Properties": {
                    "Name": queue_name,
                    "PricingPlan": "ON_DEMAND",
                    "Status": queue_status,
                    "Tags": {"sim2real-mc": queue_name},
                },
            },
            "JobTemplate": {
                "Type": "AWS::MediaConvert::JobTemplate",
                "Properties": {
                    "Name": jt_name,
                    "SettingsJson": _job_template_settings(destination),
                    "Queue": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "Tags": {"sim2real-mc": jt_name},
                },
            },
            "Preset": {
                "Type": "AWS::MediaConvert::Preset",
                "Properties": {"Name": preset_name, "SettingsJson": _H264_SETTINGS,
                               "Tags": {"sim2real-mc": preset_name}},
            },
        },
        "Outputs": {
            "QueueRef": {"Value": {"Ref": "Queue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            "JobTemplateRef": {"Value": {"Ref": "JobTemplate"}},
            "JobTemplateArn": {"Value": {"Fn::GetAtt": ["JobTemplate", "Arn"]}},
            "PresetRef": {"Value": {"Ref": "Preset"}},
            "PresetArn": {"Value": {"Fn::GetAtt": ["Preset", "Arn"]}},
        },
    })


def _own_tags(mc, arn: str) -> dict:
    """The resource's tags without the propagated stack tag and the aws: system tags."""
    found = mc.list_tags_for_resource(Arn=arn)["ResourceTags"]["Tags"]
    return {k: v for k, v in found.items() if k != "sim2real" and not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation MediaConvert Queue, JobTemplate and Preset read back through MediaConvert.

    Each Ref and Arn GetAtt match MediaConvert's list entry, every set property and tag reads
    back, an update pauses the same queue in place, and the stack delete removes all three.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediaconvert-queue.html
    """
    mc = ctx.client("mediaconvert")
    cfn = ctx.client("cloudformation")
    names = (ctx.unique_name("sim2real-mcq-"), ctx.unique_name("sim2real-mcjt-"),
             ctx.unique_name("sim2real-mcp-"))
    queue_name, jt_name, preset_name = names
    # A run-scoped destination the template only names; no job ever writes to it.
    destination = f"s3://{jt_name.lower()}/out/"

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mcstack-"),
                            _template(names, destination, "ACTIVE"))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Each Ref and Arn GetAtt against an independent read: the list entry under its name.
    for op, key, name, prefix in (("list_queues", "Queues", queue_name, "Queue"),
                                  ("list_job_templates", "JobTemplates", jt_name, "JobTemplate"),
                                  ("list_presets", "Presets", preset_name, "Preset")):
        listed = [(x["Name"], x["Arn"]) for x in paginate(mc, op, key) if x["Name"] == name]
        assert listed == [(out[f"{prefix}Ref"], out[f"{prefix}Arn"])], (
            f"{op} lists {listed!r}; Ref/GetAtt are {out[f'{prefix}Ref']!r}/{out[f'{prefix}Arn']!r}"
        )

    queue = mc.get_queue(Name=queue_name)["Queue"]
    got = (queue["PricingPlan"], queue["Status"], _own_tags(mc, out["QueueArn"]))
    assert got == ("ON_DEMAND", "ACTIVE", {"sim2real-mc": queue_name}), f"queue reads {got!r}"
    created_at = queue["CreatedAt"]

    jt = mc.get_job_template(Name=jt_name)["JobTemplate"]
    group = jt["Settings"]["OutputGroups"][0]
    output = group["Outputs"][0]
    got = (jt["Queue"], len(jt["Settings"]["OutputGroups"]), group["Name"],
           group["OutputGroupSettings"]["Type"],
           group["OutputGroupSettings"]["FileGroupSettings"]["Destination"],
           output["ContainerSettings"]["Container"],
           output["VideoDescription"]["CodecSettings"]["Codec"],
           {k: output["VideoDescription"]["CodecSettings"]["H264Settings"][k]
            for k in ("RateControlMode", "Bitrate")},
           _own_tags(mc, out["JobTemplateArn"]))
    want = (out["QueueArn"], 1, "File Group", "FILE_GROUP_SETTINGS", destination, "MP4", "H_264",
            {"RateControlMode": "CBR", "Bitrate": 1000000}, {"sim2real-mc": jt_name})
    assert got == want, f"job template reads {got!r}, expected {want!r}"

    preset = mc.get_preset(Name=preset_name)["Preset"]
    settings = preset["Settings"]
    got = (settings["ContainerSettings"]["Container"],
           settings["VideoDescription"]["CodecSettings"]["Codec"],
           {k: settings["VideoDescription"]["CodecSettings"]["H264Settings"][k]
            for k in ("RateControlMode", "Bitrate")},
           _own_tags(mc, out["PresetArn"]))
    want = ("MP4", "H_264", {"RateControlMode": "CBR", "Bitrate": 1000000},
            {"sim2real-mc": preset_name})
    assert got == want, f"preset reads {got!r}, expected {want!r}"

    # An in-place update: the same queue (same CreatedAt) pauses.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(names, destination, "PAUSED"))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"queue-pausing update ended {status!r}"
    updated = mc.get_queue(Name=queue_name)["Queue"]
    got = (updated["Status"], updated["CreatedAt"])
    assert got == ("PAUSED", created_at), f"after the update the queue reads {got!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: mc.get_queue(Name=queue_name), *_GONE)
    expect_error(lambda: mc.get_job_template(Name=jt_name), *_GONE)
    expect_error(lambda: mc.get_preset(Name=preset_name), *_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
