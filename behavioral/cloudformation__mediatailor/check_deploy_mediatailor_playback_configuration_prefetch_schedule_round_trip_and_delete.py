"""deploy-mediatailor-playback-configuration-prefetch-schedule-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mediatailor-playback-configuration-prefetch-schedule-round-trip-and-delete"
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


_VIDEO_URL = "https://example.com/video"
_ADS_URL = "https://example.com/ads?[timestamp]"


def _template(pc_name, pf_name, with_schedule=True):
    resources = {
        "PlaybackConfiguration": {
            "Type": "AWS::MediaTailor::PlaybackConfiguration",
            "Properties": {
                "Name": pc_name,
                "VideoContentSourceUrl": _VIDEO_URL,
                "AdDecisionServerUrl": _ADS_URL,
                "Tags": [{"Key": "sim2real-pc", "Value": pc_name}],
            },
        },
    }
    outputs = {"PlaybackConfigurationRef": {"Value": {"Ref": "PlaybackConfiguration"}}}
    if with_schedule:
        resources["PrefetchSchedule"] = {
            "Type": "AWS::MediaTailor::PrefetchSchedule",
            "Properties": {
                "Name": pf_name,
                "PlaybackConfigurationName": {"Ref": "PlaybackConfiguration"},
                "Retrieval": {"EndTime": {"Ref": "RetrievalEndTime"}},
                "Consumption": {"EndTime": {"Ref": "ConsumptionEndTime"}},
            },
        }
        outputs["PrefetchScheduleRef"] = {"Value": {"Ref": "PrefetchSchedule"}}
        outputs["PrefetchScheduleArn"] = {"Value": {"Fn::GetAtt": ["PrefetchSchedule", "Arn"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RetrievalEndTime": {"Type": "String"},
            "ConsumptionEndTime": {"Type": "String"},
        },
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation PlaybackConfiguration and a PrefetchSchedule attached to it read back
    through MediaTailor with the template's URLs, tags and windows; an update dropping the
    schedule removes it while the configuration answers, and the stack delete removes the rest.
    """
    cfn = ctx.client("cloudformation")
    mt = ctx.client("mediatailor")
    stack_name = ctx.unique_name("sim2real-behav-cfn-mtpf-")
    pc_name = ctx.unique_name("sim2real_behav_pc_")
    pf_name = ctx.unique_name("sim2real_behav_pf_")
    # Windows in the future, set by parameter: no assert depends on them elapsing.
    retrieval_end = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    consumption_end = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = [
        {"ParameterKey": "RetrievalEndTime", "ParameterValue": retrieval_end},
        {"ParameterKey": "ConsumptionEndTime", "ParameterValue": consumption_end},
    ]

    stack_id = create_stack(ctx, cfn, stack_name, _template(pc_name, pf_name), Parameters=params)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # PlaybackConfiguration: Ref against the independent list entry; every templated property.
    configs = [c for c in paginate(mt, "list_playback_configurations", "Items")
               if c["Name"] == pc_name]
    got = [(c["Name"], c["VideoContentSourceUrl"], c["AdDecisionServerUrl"]) for c in configs]
    assert got == [(outputs["PlaybackConfigurationRef"], _VIDEO_URL, _ADS_URL)], (
        f"ListPlaybackConfigurations entries named {pc_name!r}: {got!r}"
    )
    pc_arn = configs[0]["PlaybackConfigurationArn"]

    # PrefetchSchedule: Ref and GetAtt Arn against the schedule listed under the configuration.
    schedules = [s for s in paginate(mt, "list_prefetch_schedules", "Items",
                                     PlaybackConfigurationName=pc_name)
                 if s["Name"] == pf_name]
    assert [s["Arn"] for s in schedules] == [outputs["PrefetchScheduleRef"]], (
        f"ListPrefetchSchedules entries named {pf_name!r}: {schedules!r}"
    )
    assert outputs["PrefetchScheduleArn"] == outputs["PrefetchScheduleRef"], (
        f"GetAtt Arn {outputs['PrefetchScheduleArn']!r} != Ref {outputs['PrefetchScheduleRef']!r}"
    )
    pf = schedules[0]
    got = (pf["Retrieval"]["EndTime"].strftime("%Y-%m-%dT%H:%M:%SZ"),
           pf["Consumption"]["EndTime"].strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert got == (retrieval_end, consumption_end), f"(Retrieval, Consumption) EndTime {got!r}"

    got_tags = {k: v for k, v in mt.list_tags_for_resource(ResourceArn=pc_arn)["Tags"].items()
                if not k.startswith("aws:")}
    assert got_tags == {"sim2real": stack_name, "sim2real-pc": pc_name}, f"tags {got_tags!r}"

    # Child first: an update dropping the schedule leaves the configuration's schedule list
    # exactly empty while the configuration still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(pc_name, pf_name, False),
                     Parameters=params)
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"schedule-removing update ended {status!r}"
    left = paginate(mt, "list_prefetch_schedules", "Items", PlaybackConfigurationName=pc_name)
    assert left == [], f"prefetch schedules still listed after the update: {left!r}"
    still = mt.get_playback_configuration(Name=pc_name)["PlaybackConfigurationArn"]
    assert still == pc_arn, f"playback configuration after the update {still!r} != {pc_arn!r}"

    delete_stack(cfn, stack_id)
    gone = ("NotFoundException", f"configuration {pc_name} not found for awsAccountId: {ctx.account}")
    expect_error(lambda: mt.get_playback_configuration(Name=pc_name), *gone)
    schedule_gone = ("NotFoundException", f"PlaybackConfiguration {pc_name} not found")
    expect_error(lambda: mt.get_prefetch_schedule(Name=pf_name, PlaybackConfigurationName=pc_name),
                 *schedule_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
