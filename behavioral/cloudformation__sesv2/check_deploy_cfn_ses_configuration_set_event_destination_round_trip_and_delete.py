"""deploy-cfn-ses-configuration-set-event-destination-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ses-configuration-set-event-destination-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "sesv2"]

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

_DIMENSION_NAME = "sim2real-dim"
_DIMENSION_DEFAULT = "sim2real-default"


def _template(ed_name: str, with_destination=True) -> str:
    resources = {"Cs": {"Type": "AWS::SES::ConfigurationSet",
                        "Properties": {"Name": {"Ref": "CsNameParam"}}}}
    outputs = {"CsNameRef": {"Value": {"Ref": "Cs"}}}
    if with_destination:
        resources["Ed"] = {
            "Type": "AWS::SES::ConfigurationSetEventDestination",
            "Properties": {
                "ConfigurationSetName": {"Ref": "Cs"},
                "EventDestination": {
                    "Name": ed_name,
                    "Enabled": True,
                    "MatchingEventTypes": ["SEND", "BOUNCE"],
                    "CloudWatchDestination": {"DimensionConfigurations": [{
                        "DimensionName": _DIMENSION_NAME,
                        "DimensionValueSource": "MESSAGE_TAG",
                        "DefaultDimensionValue": _DIMENSION_DEFAULT,
                    }]},
                },
            },
        }
        outputs["EdId"] = {"Value": {"Fn::GetAtt": ["Ed", "Id"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"CsNameParam": {"Type": "String"}},
        "Resources": resources,
        "Outputs": outputs,
    })


def _pages(fn, key, **kw):
    """Every ``key`` item across NextToken pages of an SESv2 list call without a paginator."""
    out = []
    while True:
        page = fn(**kw)
        out += page.get(key, [])
        if not page.get("NextToken"):
            return out
        kw = {**kw, "NextToken": page["NextToken"]}


def _tags(sesv2, arn):
    return {t["Key"]: t["Value"] for t in sesv2.list_tags_for_resource(ResourceArn=arn)["Tags"]
            if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::SES::ConfigurationSetEventDestination reads back through SESv2, a stack
    update removing it clears it while the same configuration set (an out-of-band tag marker still
    on it) survives, and deleting the stack removes the set too.
    """
    sesv2 = ctx.client("sesv2")
    cfn = ctx.client("cloudformation")
    cs_name = ctx.unique_name("sim2real-sesed-cs-")
    ed_name = ctx.unique_name("sim2real-sesed-ed-")
    params = [{"ParameterKey": "CsNameParam", "ParameterValue": cs_name}]

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-sesed-stack-"),
                            _template(ed_name), Parameters=params)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    listed = [n for n in _pages(sesv2.list_configuration_sets, "ConfigurationSets")
              if n == cs_name]
    assert listed == [outputs["CsNameRef"]], (
        f"ListConfigurationSets {listed!r} for Ref {outputs['CsNameRef']!r}"
    )
    destinations = sesv2.get_configuration_set_event_destinations(
        ConfigurationSetName=cs_name
    )["EventDestinations"]
    want = [{
        "Name": ed_name,
        "Enabled": True,
        "MatchingEventTypes": ["BOUNCE", "SEND"],
        "CloudWatchDestination": {"DimensionConfigurations": [{
            "DimensionName": _DIMENSION_NAME,
            "DimensionValueSource": "MESSAGE_TAG",
            "DefaultDimensionValue": _DIMENSION_DEFAULT,
        }]},
    }]
    got = [{**d, "MatchingEventTypes": sorted(d.get("MatchingEventTypes", []))}
           for d in destinations]
    assert got == want, f"event destinations {got!r}, expected {want!r}"
    assert outputs["EdId"] == got[0]["Name"] == ed_name, (
        f"GetAtt Id {outputs['EdId']!r}, listed name {got[0]['Name']!r}, declared {ed_name!r}"
    )

    # An out-of-band marker on the set: the same set must still carry it after the update.
    partition = stack_id.split(":")[1]
    cs_arn = f"arn:{partition}:ses:{ctx.region}:{ctx.account}:configuration-set/{cs_name}"
    marker = ctx.unique_name("sim2real-sesed-marker-")
    sesv2.tag_resource(ResourceArn=cs_arn, Tags=[{"Key": "sim2real-marker", "Value": marker}])

    # Child first: the update drops the event destination; the set answers with none left.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(ed_name, with_destination=False),
                     Parameters=params)
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"destination-dropping update ended {status!r}"
    remaining = sesv2.get_configuration_set_event_destinations(
        ConfigurationSetName=cs_name
    ).get("EventDestinations", [])
    assert remaining == [], f"event destinations on {cs_name!r} after the update: {remaining!r}"
    marker_after = _tags(sesv2, cs_arn).get("sim2real-marker")
    assert marker_after == marker, (
        f"the configuration set's marker reads {marker_after!r} after the update, set {marker!r}"
    )

    delete_stack(cfn, stack_id)
    gone = ("NotFoundException", f"Configuration set <{cs_name}> does not exist.")
    expect_error(lambda: sesv2.get_configuration_set(ConfigurationSetName=cs_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
