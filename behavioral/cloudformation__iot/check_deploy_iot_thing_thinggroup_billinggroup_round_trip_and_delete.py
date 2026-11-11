"""deploy-iot-thing-thinggroup-billinggroup-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iot-thing-thinggroup-billinggroup-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

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


# ---- Check-specific: the template, then run(). ----

_THING_GONE = ("ResourceNotFoundException", "Thing <account>:<name> not found.")
_GROUP_GONE = ("ResourceNotFoundException", "ThingGroup <account>:<name> not found.")
_BILLING_GONE = ("ResourceNotFoundException", "BillingGroup <account>:<name> not found.")


def _template(thing_name: str, group_name: str, billing_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Thing": {
                "Type": "AWS::IoT::Thing",
                "Properties": {
                    "ThingName": thing_name,
                    "AttributePayload": {"Attributes": {"sim2real": "thing"}},
                },
            },
            "Group": {
                "Type": "AWS::IoT::ThingGroup",
                "Properties": {
                    "ThingGroupName": group_name,
                    "ThingGroupProperties": {"ThingGroupDescription": "sim2real thing group"},
                },
            },
            "Billing": {
                "Type": "AWS::IoT::BillingGroup",
                "Properties": {
                    "BillingGroupName": billing_name,
                    "BillingGroupProperties": {"BillingGroupDescription": "sim2real billing group"},
                },
            },
        },
        "Outputs": {
            "ThingRef": {"Value": {"Ref": "Thing"}},
            "ThingArn": {"Value": {"Fn::GetAtt": ["Thing", "Arn"]}},
            "GroupRef": {"Value": {"Ref": "Group"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
            "BillingRef": {"Value": {"Ref": "Billing"}},
            "BillingArn": {"Value": {"Fn::GetAtt": ["Billing", "Arn"]}},
        },
    })


def _refusal(fn, account, *names):
    """(Error.Code, Error.Message masked) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message") or "", account, *names)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack deploying AWS::IoT::Thing, AWS::IoT::ThingGroup and
    AWS::IoT::BillingGroup provisions resources IoT's own API reads back with the
    declared properties; deleting the stack removes all three from IoT.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-thing.html
    """
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-iotreg-")
    thing_name = ctx.unique_name("sim2real-iot-thing-")
    group_name = ctx.unique_name("sim2real-iot-group-")
    billing_name = ctx.unique_name("sim2real-iot-billing-")

    stack_id = create_stack(ctx, cfn, stack, _template(thing_name, group_name, billing_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)

    # AWS::IoT::Thing
    assert outputs["ThingRef"] == thing_name, (
        f"Ref of the Thing resource is {outputs['ThingRef']!r}, expected the thing name {thing_name!r}"
    )
    thing = iot.describe_thing(thingName=thing_name)
    assert thing["thingName"] == thing_name, (
        f"DescribeThing returned thingName {thing['thingName']!r}, expected {thing_name!r}"
    )
    assert thing["attributes"] == {"sim2real": "thing"}, (
        f"expected attributes {{'sim2real': 'thing'}}, DescribeThing reports {thing['attributes']!r}"
    )
    assert outputs["ThingArn"] == thing["thingArn"], (
        f"GetAtt Arn is {outputs['ThingArn']!r}, DescribeThing reports {thing['thingArn']!r}"
    )

    # AWS::IoT::ThingGroup
    group = iot.describe_thing_group(thingGroupName=group_name)
    assert outputs["GroupRef"] == group_name, (
        f"Ref of the ThingGroup resource is {outputs['GroupRef']!r}, expected the group name {group_name!r}"
    )
    assert group["thingGroupName"] == group_name, (
        f"DescribeThingGroup returned thingGroupName {group['thingGroupName']!r}, expected {group_name!r}"
    )
    assert group["thingGroupProperties"]["thingGroupDescription"] == "sim2real thing group", (
        "expected thingGroupDescription 'sim2real thing group', DescribeThingGroup reports "
        f"{group['thingGroupProperties']!r}"
    )
    assert outputs["GroupArn"] == group["thingGroupArn"], (
        f"GetAtt Arn is {outputs['GroupArn']!r}, DescribeThingGroup reports {group['thingGroupArn']!r}"
    )

    # AWS::IoT::BillingGroup
    billing = iot.describe_billing_group(billingGroupName=billing_name)
    assert outputs["BillingRef"] == billing_name, (
        f"Ref of the BillingGroup resource is {outputs['BillingRef']!r}, expected the billing group "
        f"name {billing_name!r}"
    )
    assert billing["billingGroupName"] == billing_name, (
        f"DescribeBillingGroup returned billingGroupName {billing['billingGroupName']!r}, expected "
        f"{billing_name!r}"
    )
    assert billing["billingGroupProperties"]["billingGroupDescription"] == "sim2real billing group", (
        "expected billingGroupDescription 'sim2real billing group', DescribeBillingGroup reports "
        f"{billing['billingGroupProperties']!r}"
    )
    assert outputs["BillingArn"] == billing["billingGroupArn"], (
        f"GetAtt Arn is {outputs['BillingArn']!r}, DescribeBillingGroup reports "
        f"{billing['billingGroupArn']!r}"
    )

    delete_stack(cfn, stack_id)

    got = _refusal(lambda: iot.describe_thing(thingName=thing_name), ctx.account, thing_name)
    assert got == _THING_GONE, f"DescribeThing of the deleted thing answered {got!r}"
    got = _refusal(lambda: iot.describe_thing_group(thingGroupName=group_name), ctx.account,
                   group_name)
    assert got == _GROUP_GONE, f"DescribeThingGroup of the deleted group answered {got!r}"
    got = _refusal(lambda: iot.describe_billing_group(billingGroupName=billing_name), ctx.account,
                   billing_name)
    assert got == _BILLING_GONE, f"DescribeBillingGroup of the deleted billing group answered {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
