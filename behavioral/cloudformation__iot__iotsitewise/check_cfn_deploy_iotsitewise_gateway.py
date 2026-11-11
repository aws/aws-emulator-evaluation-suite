"""cfn-deploy-iotsitewise-gateway."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iotsitewise-gateway"

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

#: An IoT Thing and an IoTSiteWise Gateway record naming it as its Greengrass V2 core device.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: IoTSiteWise gateway provisioned through CloudFormation

Resources:
  Thing:
    Type: AWS::IoT::Thing
    Properties:
      ThingName: !Sub 'sim2real-${AWS::StackName}-thing'

  Gateway:
    Type: AWS::IoTSiteWise::Gateway
    Properties:
      GatewayName: !Sub 'sim2real-${AWS::StackName}-gw'
      GatewayPlatform:
        GreengrassV2:
          CoreDeviceThingName: !Ref Thing

Outputs:
  ThingName:
    Value: !Ref Thing
  ThingArn:
    Value: !GetAtt Thing.Arn
  GatewayId:
    Value: !Ref Gateway
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::IoTSiteWise::Gateway on an AWS::IoT::Thing core device reads back
    through IoT SiteWise and IoT with its name, platform, Ref and GetAtt, and deleting the stack
    removes both with each service's exact not-found error."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    stack_id = create_stack(ctx, cfn, stack_name, _TEMPLATE)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"Stack {stack_name} ended in {status}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    thing_name = outputs["ThingName"]
    gateway_id = outputs["GatewayId"]

    expected_thing = f"sim2real-{stack_name}-thing"
    assert thing_name == expected_thing, f"expected Ref Thing {expected_thing!r}, got {thing_name!r}"

    iot = ctx.client("iot")
    thing = iot.describe_thing(thingName=thing_name)
    assert thing["thingName"] == thing_name, (
        f"expected IoT to hold thing {thing_name!r}, got {thing['thingName']!r}"
    )
    assert thing["thingArn"] == outputs["ThingArn"], (
        f"expected GetAtt Thing.Arn {outputs['ThingArn']!r} to be IoT's thingArn {thing['thingArn']!r}"
    )

    sw = ctx.client("iotsitewise")
    expected_name = f"sim2real-{stack_name}-gw"
    listed = [g["gatewayId"] for g in paginate(sw, "list_gateways", "gatewaySummaries")
              if g["gatewayName"] == expected_name]
    assert listed == [gateway_id], (
        f"expected Ref Gateway to be the one gateway IoT SiteWise lists as {expected_name!r}, "
        f"Ref gave {gateway_id!r} and ListGateways has {listed!r}"
    )
    gateway = sw.describe_gateway(gatewayId=gateway_id)
    assert gateway["gatewayName"] == expected_name, (
        f"expected the template's GatewayName {expected_name!r}, got {gateway['gatewayName']!r}"
    )
    platform = gateway["gatewayPlatform"]
    assert list(platform) == ["greengrassV2"] and (
        platform["greengrassV2"]["coreDeviceThingName"] == thing_name
    ), (
        f"expected the gateway's platform to read back Greengrass V2 core device {thing_name!r}, "
        f"got {platform!r}"
    )

    # Tear down in the body: delete the stack, then prove both resources gone through their
    # owning services.
    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack_name} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack_name), *stack_gone)
    gateway_gone = (
        "ResourceNotFoundException",
        f"No gateway with ID {gateway_id} was found. "
        "Please verify that you supplied the correct gateway ID and try again.",
    )
    until_raises(lambda: sw.describe_gateway(gatewayId=gateway_id), timeout_s=120.0)
    expect_error(lambda: sw.describe_gateway(gatewayId=gateway_id), *gateway_gone)
    # IoT names the thing by account and name.
    thing_gone = ("ResourceNotFoundException", f"Thing {ctx.account}:{thing_name} not found.")
    until_raises(lambda: iot.describe_thing(thingName=thing_name), timeout_s=120.0)
    expect_error(lambda: iot.describe_thing(thingName=thing_name), *thing_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
