"""deploy-braket-spendinglimit-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime
from decimal import Decimal

from behavioral_harness import tags

CHECK = "deploy-braket-spendinglimit-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["braket", "cloudformation"]

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


# ---- Check-specific: the template, then run(). ----

# A QPU is resident in one Region each and none is in every Region, while CreateSpendingLimit
# accepts only a QPU: the check pins to a Region with ONLINE QPUs instead of following ctx.region.
_DEVICE_REGION = "us-east-1"
_SPENDING_LIMIT = "5.00"


def _template(device_arn):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Limit": {
                "Type": "AWS::Braket::SpendingLimit",
                "Properties": {"DeviceArn": device_arn, "SpendingLimit": _SPENDING_LIMIT},
            },
        },
        "Outputs": {
            "LimitRef": {"Value": {"Ref": "Limit"}},
            "SpendingLimitArn": {"Value": {"Fn::GetAtt": ["Limit", "SpendingLimitArn"]}},
            "CreatedAt": {"Value": {"Fn::GetAtt": ["Limit", "CreatedAt"]}},
        },
    })


def _online_device_arn(braket, device_type):
    """The first ONLINE device of ``device_type`` Braket lists in this Region."""
    devices = paginate(braket, "search_devices", "devices", filters=[])
    online = sorted(d["deviceArn"] for d in devices
                    if d["deviceType"] == device_type and d["deviceStatus"] == "ONLINE")
    assert online, f"no ONLINE {device_type} device found in {braket.meta.region_name!r}"
    return online[0]


def _limits_for(braket, device_arn):
    return paginate(braket, "search_spending_limits", "spendingLimits", filters=[
        {"name": "deviceArn", "values": [device_arn], "operator": "EQUAL"}])


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Braket SpendingLimit reads back through SearchSpendingLimits.

    Ref and GetAtt match the independent entry with the templated device and amount, and deleting
    the stack removes it.

    Reference: https://docs.aws.amazon.com/braket/latest/APIReference/API_SpendingLimitSummary.html
    """
    cfn = ctx.client("cloudformation", region=_DEVICE_REGION)
    braket = ctx.client("braket", region=_DEVICE_REGION)
    device_arn = _online_device_arn(braket, "QPU")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-braketsl-"), _template(device_arn))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Ref and GetAtt against the device's independent SearchSpendingLimits listing.
    new = [s for s in _limits_for(braket, device_arn) if s["spendingLimitArn"] == out["LimitRef"]]
    assert len(new) == 1, f"SearchSpendingLimits lists {len(new)} entries for the Ref"
    found = new[0]
    assert out["SpendingLimitArn"] == found["spendingLimitArn"], (
        f"GetAtt SpendingLimitArn {out['SpendingLimitArn']!r} != {found['spendingLimitArn']!r}"
    )
    created = datetime.fromisoformat(out["CreatedAt"].replace("Z", "+00:00"))
    got = (found["deviceArn"], Decimal(found["spendingLimit"]), found["createdAt"])
    assert got == (device_arn, Decimal(_SPENDING_LIMIT), created), (
        f"SearchSpendingLimits reads {got!r}"
    )

    delete_stack(cfn, stack_id)
    left = [s for s in _limits_for(braket, device_arn) if s["spendingLimitArn"] == out["LimitRef"]]
    assert left == [], f"SearchSpendingLimits still includes the deleted limit: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
