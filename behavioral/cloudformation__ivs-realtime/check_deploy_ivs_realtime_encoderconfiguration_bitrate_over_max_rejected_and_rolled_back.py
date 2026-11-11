"""deploy-ivs-realtime-encoderconfiguration-bitrate-over-max-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ivs-realtime-encoderconfiguration-bitrate-over-max-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ivs-realtime"]

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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_SCHEMA_MAX_BITRATE = 8500000
_GOOD_VIDEO = {"Width": 1280, "Height": 720, "Framerate": 30, "Bitrate": 2500000}
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _bad_template(name: str, tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Encoder": {
                "Type": "AWS::IVS::EncoderConfiguration",
                "Properties": {
                    "Name": name,
                    "Video": {**_GOOD_VIDEO, "Bitrate": _SCHEMA_MAX_BITRATE + 1},
                    "Tags": t,
                },
            },
        },
    })


def _good_template(name: str, tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Encoder": {
                "Type": "AWS::IVS::EncoderConfiguration",
                "Properties": {"Name": name, "Video": _GOOD_VIDEO, "Tags": t},
            },
        },
        "Outputs": {
            "EncoderRef": {"Value": {"Ref": "Encoder"}},
            "EncoderArn": {"Value": {"Fn::GetAtt": ["Encoder", "Arn"]}},
        },
    })


def _encoder_configurations(ivsrt) -> list[dict]:
    """Every ListEncoderConfigurations summary, following nextToken (botocore has no paginator)."""
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        page = ivsrt.list_encoder_configurations(**kwargs)
        out.extend(page.get("encoderConfigurations", []))
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _user_tags(tags_: dict) -> dict:
    """Tags without the aws:-prefixed system tags CloudFormation adds."""
    return {k: v for k, v in tags_.items() if not k.startswith("aws:")}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::IVS::EncoderConfiguration with Video.Bitrate above the registry
    schema's maximum is rejected before the resource is created, the stack rolls back, and the
    same template with a valid bitrate still deploys and reads back through ivs-realtime.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ivs-encoderconfiguration.html
    """
    cfn = ctx.client("cloudformation")
    ivsrt = ctx.client("ivs-realtime")
    bad_stack = ctx.unique_name("sim2real-cfnivsrtbad-")
    bad_name = ctx.unique_name("sim2real-cfnivsrtbad-enc-")

    bad_id = create_stack(ctx, cfn, bad_stack, _bad_template(bad_name, CHECK))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    events = stack_events(cfn, bad_id)
    reason = failed_reason(events, bad_stack)
    assert reason == _STACK_REASON, f"expected reason {_STACK_REASON!r}, got {reason!r}"

    bad_bitrate = _SCHEMA_MAX_BITRATE + 1
    found = validation_rows(cfn, bad_id)
    want = [(
        "Encoder", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        f"#/Video/Bitrate: {bad_bitrate} is not less or equal to {_SCHEMA_MAX_BITRATE}",
        "/Resources/Encoder/Properties/Video/Bitrate",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"

    # The rejection precedes provisioning: no Encoder event, and ivs-realtime never saw the name.
    resource_events = [e for e in events if e["LogicalResourceId"] == "Encoder"]
    assert resource_events == [], (
        f"expected no event for the Encoder resource, the schema rejection never reached it, "
        f"got {resource_events!r}"
    )
    assert bad_name not in {e["name"] for e in _encoder_configurations(ivsrt)}, (
        f"the rejected encoder name {bad_name!r} unexpectedly exists in ListEncoderConfigurations"
    )

    delete_stack(cfn, bad_id)

    # Positive control: the same template with Bitrate in range deploys and reads back.
    good_stack = ctx.unique_name("sim2real-cfnivsrtgood-")
    good_name = ctx.unique_name("sim2real-cfnivsrtgood-enc-")
    good_id = create_stack(ctx, cfn, good_stack, _good_template(good_name, CHECK))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack {good_stack!r} ended {status!r}: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    outputs = stack_outputs(cfn, good_id)
    listed = [e["arn"] for e in _encoder_configurations(ivsrt) if e["name"] == good_name]
    assert listed == [outputs["EncoderRef"]], (
        f"ListEncoderConfigurations arns for {good_name!r} are {listed!r}, expected the Ref "
        f"{outputs['EncoderRef']!r}"
    )
    control = ivsrt.get_encoder_configuration(arn=outputs["EncoderRef"])["encoderConfiguration"]
    assert control["arn"] == outputs["EncoderArn"], (
        f"GetEncoderConfiguration arn {control['arn']!r} != GetAtt Arn {outputs['EncoderArn']!r}"
    )
    assert control["name"] == good_name, f"control encoder name {control['name']!r}"
    want_video = {
        "width": _GOOD_VIDEO["Width"], "height": _GOOD_VIDEO["Height"],
        "framerate": float(_GOOD_VIDEO["Framerate"]), "bitrate": _GOOD_VIDEO["Bitrate"],
    }
    assert control["video"] == want_video, (
        f"control encoder video {control['video']!r}, expected {want_video!r}"
    )
    want_tags = {"sim2real": good_stack, "sim2real-check": CHECK}
    assert _user_tags(control.get("tags", {})) == want_tags, (
        f"control encoder tags {control.get('tags')!r}, expected {want_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
