"""deploy-globalaccelerator-accelerator-listener-endpointgroup-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-globalaccelerator-accelerator-listener-endpointgroup-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "globalaccelerator"]

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

_PROTOCOL = "TCP"
_PORT_RANGES = [{"FromPort": 443, "ToPort": 443}]


def _own_tags(ga, arn):
    return {t["Key"]: t["Value"] for t in ga.list_tags_for_resource(ResourceArn=arn)["Tags"]
            if not t["Key"].startswith("aws:")}


def _accelerators(ga, name):
    return [a for a in paginate(ga, "list_accelerators", "Accelerators") if a["Name"] == name]
_CLIENT_AFFINITY = "SOURCE_IP"
_HEALTH_CHECK_INTERVAL_S = 10
_THRESHOLD_COUNT = 5
_TRAFFIC_DIAL_PCT = 80.0


def _template(name, with_children=True):
    # Enabled False: the accelerator's static addresses never accept traffic.
    resources = {"Accelerator": {"Type": "AWS::GlobalAccelerator::Accelerator", "Properties": {
        "Name": name, "Enabled": False, "Tags": [{"Key": "sim2real-ga", "Value": name}]}}}
    outputs = {
        "AcceleratorArn": {"Value": {"Ref": "Accelerator"}},
        "AcceleratorDnsName": {"Value": {"Fn::GetAtt": ["Accelerator", "DnsName"]}},
        "AcceleratorIpv4Addresses": {
            "Value": {"Fn::Join": [",", {"Fn::GetAtt": ["Accelerator", "Ipv4Addresses"]}]}},
    }
    if with_children:
        resources["Listener"] = {"Type": "AWS::GlobalAccelerator::Listener", "Properties": {
            "AcceleratorArn": {"Ref": "Accelerator"}, "Protocol": _PROTOCOL,
            "PortRanges": _PORT_RANGES, "ClientAffinity": _CLIENT_AFFINITY}}
        resources["EndpointGroup"] = {"Type": "AWS::GlobalAccelerator::EndpointGroup",
                                      "Properties": {
            "ListenerArn": {"Ref": "Listener"},
            "EndpointGroupRegion": {"Ref": "AWS::Region"},
            "HealthCheckIntervalSeconds": _HEALTH_CHECK_INTERVAL_S,
            "ThresholdCount": _THRESHOLD_COUNT,
            "TrafficDialPercentage": _TRAFFIC_DIAL_PCT}}
        outputs["ListenerArn"] = {"Value": {"Ref": "Listener"}}
        outputs["EndpointGroupArn"] = {"Value": {"Ref": "EndpointGroup"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation accelerator, listener and endpoint group read back through Global Accelerator.

    An update dropping the listener and endpoint group removes both while the accelerator
    answers, and deleting the stack removes the accelerator.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-globalaccelerator-accelerator.html
    """
    cf = ctx.client("cloudformation")
    ga = ctx.client("globalaccelerator")
    stack = ctx.unique_name("sim2real-gastack-")
    name = ctx.unique_name("sim2real-ga-")

    stack_id = create_stack(ctx, cf, stack, _template(name))
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Each Ref against an independent listing: accelerators by name, then each parent's children.
    listed = [a["AcceleratorArn"] for a in _accelerators(ga, name)]
    assert listed == [out["AcceleratorArn"]], f"ListAccelerators {listed!r}"
    acc = ga.describe_accelerator(AcceleratorArn=listed[0])["Accelerator"]
    got = (acc["Name"], acc["Enabled"], acc["DnsName"], acc["Status"],
           [sorted(s["IpAddresses"]) for s in acc["IpSets"]], _own_tags(ga, listed[0]))
    want = (name, False, out["AcceleratorDnsName"], "DEPLOYED",
            [sorted(out["AcceleratorIpv4Addresses"].split(","))], {"sim2real": stack,
                                                                   "sim2real-ga": name})
    assert got == want, f"DescribeAccelerator {got!r}, expected {want!r}"

    listeners = paginate(ga, "list_listeners", "Listeners", AcceleratorArn=listed[0])
    got_l = [(x["ListenerArn"], x["Protocol"], x["PortRanges"], x["ClientAffinity"])
             for x in listeners]
    assert got_l == [(out["ListenerArn"], _PROTOCOL, _PORT_RANGES, _CLIENT_AFFINITY)], (
        f"ListListeners {got_l!r}"
    )
    groups = paginate(ga, "list_endpoint_groups", "EndpointGroups", ListenerArn=got_l[0][0])
    got_g = [(g["EndpointGroupArn"], g["EndpointGroupRegion"], g["HealthCheckIntervalSeconds"],
              g["ThresholdCount"], g["TrafficDialPercentage"], g["EndpointDescriptions"])
             for g in groups]
    assert got_g == [(out["EndpointGroupArn"], ctx.region, _HEALTH_CHECK_INTERVAL_S,
                      _THRESHOLD_COUNT, _TRAFFIC_DIAL_PCT, [])], f"ListEndpointGroups {got_g!r}"

    # The children alone: an update dropping them leaves the accelerator with no listener.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(name, with_children=False))
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    not_found = (
        "EndpointGroupNotFoundException",
        f"EndpointGroup {out['EndpointGroupArn']} does not exist."
    )
    expect_error(
        lambda: ga.describe_endpoint_group(EndpointGroupArn=out["EndpointGroupArn"]),
        *not_found,
    )
    not_found_2 = ("ListenerNotFoundException", f"Listener {out['ListenerArn']} not found.")
    expect_error(lambda: ga.describe_listener(ListenerArn=out["ListenerArn"]), *not_found_2)
    left = paginate(ga, "list_listeners", "Listeners", AcceleratorArn=listed[0])
    assert left == [], f"the dropped listener is still listed: {left!r}"

    delete_stack(cf, stack_id)
    not_found_3 = ("AcceleratorNotFoundException", f"Accelerator {listed[0]} not found.")
    expect_error(lambda: ga.describe_accelerator(AcceleratorArn=listed[0]), *not_found_3)
    assert _accelerators(ga, name) == [], f"deleted accelerator listed: {_accelerators(ga, name)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
