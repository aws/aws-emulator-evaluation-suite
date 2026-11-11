"""cfn-iotsitewise-gateway-platform-oneof-violation-rejected."""

from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iotsitewise-gateway-platform-oneof-violation-rejected"

GROUP = "deploy"

SERVICES = ["cloudformation", "iot", "iotsitewise"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: IoTSiteWise gateway on a GreengrassV2 core device

Resources:
  Thing:
    Type: AWS::IoT::Thing
    Properties:
      ThingName: !Sub '${{AWS::StackName}}-thing'

  Gateway:
    Type: AWS::IoTSiteWise::Gateway
    Properties:
      GatewayName: !Sub '${{AWS::StackName}}-gw'
      GatewayPlatform:
        GreengrassV2:
          CoreDeviceThingName: !Ref Thing
{extra_platform}
Outputs:
  ThingName:
    Value: !Ref Thing
  GatewayId:
    Value: !Ref Gateway
"""

#: The positive control names exactly one platform (GreengrassV2).
_GOOD_TEMPLATE = _TEMPLATE.format(extra_platform="")

#: The same template with only GatewayPlatform changed to name BOTH platforms: GatewayPlatform
#: is a documented oneOf (exactly one of GreengrassV2 / SiemensIE).
_BAD_TEMPLATE = _TEMPLATE.format(
    extra_platform="        SiemensIE:\n          IotCoreThingName: !Ref Thing\n"
)

#: CloudFormation's own schema-validation refusal, as (handler message, HandlerErrorCode).
_REJECTED = (
    "Model validation failed (#/GatewayPlatform: #: only 1 subschema matches out of 2)\n"
    "#/GatewayPlatform: #: 2 subschemas matched instead of one (#/GatewayPlatform)",
    "InvalidRequest",
)


def _gateway_names(sw) -> list[str]:
    """Every gateway name in the account, all pages."""
    return [g["gatewayName"] for g in paginate(sw, "list_gateways", "gatewaySummaries")]


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A GatewayPlatform naming both platforms at once is rejected and leaves no gateway or thing;
    the same gateway with one platform deploys on its IoT core-device thing."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    sw = ctx.client("iotsitewise")
    iot = ctx.client("iot")
    good_name = ctx.unique_name("sim2real-xsvc-stk-")
    good_id = create_stack(ctx, cfn, good_name, _GOOD_TEMPLATE)
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"Stack {good_name} ended in {status}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    outputs = stack_outputs(cfn, good_id)
    partition = good_id.split(":")[1]
    good_thing = f"{good_name}-thing"
    good_gw_name = f"{good_name}-gw"
    assert outputs["ThingName"] == good_thing, (
        f"positive control: expected Ref Thing {good_thing!r}, got {outputs['ThingName']!r}"
    )
    thing = iot.describe_thing(thingName=good_thing)
    assert thing["thingName"] == good_thing, (
        f"positive control: IoT reports thingName {thing['thingName']!r}, expected {good_thing!r}"
    )
    want_thing_arn = f"arn:{partition}:iot:{ctx.region}:{ctx.account}:thing/{good_thing}"
    assert thing["thingArn"] == want_thing_arn, (
        f"positive control: IoT reports thingArn {thing['thingArn']!r}, expected {want_thing_arn!r}"
    )

    good_gateway_id = outputs["GatewayId"]
    gateway = sw.describe_gateway(gatewayId=good_gateway_id)
    assert gateway["gatewayName"] == good_gw_name, (
        f"positive control: expected gatewayName {good_gw_name!r}, got {gateway['gatewayName']!r}"
    )
    platform = gateway["gatewayPlatform"]
    assert sorted(platform) == ["greengrassV2"], (
        f"positive control: expected only a greengrassV2 platform, got {platform!r}"
    )
    assert platform["greengrassV2"]["coreDeviceThingName"] == good_thing, (
        f"positive control: expected coreDeviceThingName {good_thing!r}, got {platform!r}"
    )
    listed = [g["gatewayId"] for g in paginate(sw, "list_gateways", "gatewaySummaries")
              if g["gatewayName"] == good_gw_name]
    assert listed == [good_gateway_id], (
        f"positive control: expected ListGateways to list {good_gw_name!r} once as Ref "
        f"{good_gateway_id!r}, got {listed!r}"
    )

    bad_name = ctx.unique_name("sim2real-xsvc-stk-")
    bad_stack_id = create_stack(ctx, cfn, bad_name, _BAD_TEMPLATE)
    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"expected the two-platform gateway to roll the stack back, got {status!r}"
    )
    reason = failed_reason(stack_events(cfn, bad_stack_id), "Gateway")
    got_reason = handler_reason(reason, ctx.account, bad_name)
    assert got_reason == _REJECTED, f"expected {_REJECTED!r}, got {got_reason!r}"

    # Absence through the owning services, before any delete_stack: the rejected gateway never
    # reached IoTSiteWise, and the rollback removed the stack's thing from IoT.
    bad_gw_name = f"{bad_name}-gw"
    names = _gateway_names(sw)
    assert bad_gw_name not in names, f"expected the rejected gateway {bad_gw_name!r} absent from ListGateways"
    assert good_gw_name in names, f"expected the control gateway {good_gw_name!r} still in ListGateways"
    bad_thing = f"{bad_name}-thing"
    thing_gone = ("ResourceNotFoundException", f"Thing {ctx.account}:{bad_thing} not found.")
    expect_error(lambda: iot.describe_thing(thingName=bad_thing), *thing_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
