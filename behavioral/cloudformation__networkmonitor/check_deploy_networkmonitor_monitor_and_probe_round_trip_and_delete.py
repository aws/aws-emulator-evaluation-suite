"""deploy-networkmonitor-monitor-and-probe-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-networkmonitor-monitor-and-probe-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "networkmonitor"]

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

_VPC_CIDR = "10.99.0.0/16"
_SUBNET_CIDR = "10.99.1.0/24"
_DESTINATION = "10.99.1.10"


def _template(monitor_name: str, destination: str, tag_value: str, with_probe: bool = True) -> str:
    t = [{"Key": "sim2real-res", "Value": tag_value}]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
            "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}}},
        "Monitor": {"Type": "AWS::NetworkMonitor::Monitor", "Properties": {
            "MonitorName": monitor_name, "AggregationPeriod": 30, "Tags": t}},
    }
    outputs = {
        "VpcId": {"Value": {"Ref": "Vpc"}},
        "SubnetId": {"Value": {"Ref": "Subnet"}},
        "MonitorRef": {"Value": {"Ref": "Monitor"}},
    }
    if with_probe:
        resources["Probe"] = {"Type": "AWS::NetworkMonitor::Probe", "DependsOn": "Monitor",
                              "Properties": {
            "MonitorName": monitor_name,
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}"
                                     ":subnet/${Subnet}"},
            "Destination": destination, "Protocol": "ICMP", "Tags": t}}
        outputs.update({
            "ProbeRef": {"Value": {"Ref": "Probe"}},
            "ProbeId": {"Value": {"Fn::GetAtt": "Probe.ProbeId"}},
            "ProbeArn": {"Value": {"Fn::GetAtt": "Probe.ProbeArn"}},
            "ProbeVpcId": {"Value": {"Fn::GetAtt": "Probe.VpcId"}},
            "ProbeAddressFamily": {"Value": {"Fn::GetAtt": "Probe.AddressFamily"}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _masked_error(fn, account: str) -> tuple[str, str]:
    """``(code, message with the account masked)`` of the error ``fn()`` must raise."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], masked(exc.response["Error"]["Message"], account)
    raise AssertionError(f"expected an error but the call succeeded: {result!r}")


def _user_tags(nm, arn: str) -> dict:
    tag_map = nm.list_tags_for_resource(resourceArn=arn)["tags"]
    return {k: v for k, v in tag_map.items() if not k.startswith("aws:")}


def _settled_monitor(nm, name: str, state: str = "ACTIVE") -> dict:
    """GetMonitor polled (bounded) until the monitor and every probe read ``state``."""
    deadline = time.monotonic() + 300
    while True:
        mon = nm.get_monitor(monitorName=name)
        if mon["state"] == state and all(p["state"] == state for p in mon["probes"]):
            return mon
        if time.monotonic() > deadline:
            raise AssertionError(f"monitor {name!r} not {state} after 300s: {mon!r}")
        time.sleep(3)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation NetworkMonitor Monitor and Probe read back through NetworkMonitor.

    Every Ref, stable GetAtt, templated property and tag matches; an update dropping the Probe
    leaves the same monitor empty and INACTIVE, and deleting the stack removes the monitor.
    """
    cfn = ctx.client("cloudformation")
    nm = ctx.client("networkmonitor")
    stack = ctx.unique_name("sim2real-nmcfn-")
    monitor_name = stack
    want_tags = {"sim2real": stack, "sim2real-res": stack}

    stack_id = create_stack(ctx, cfn, stack, _template(monitor_name, _DESTINATION, stack))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # Monitor: Ref == the ARN the account's monitor listing gives for the templated name.
    listed = [m["monitorArn"] for m in paginate(nm, "list_monitors", "monitors")
              if m["monitorName"] == monitor_name]
    assert listed == [out["MonitorRef"]], f"ListMonitors for {monitor_name!r}: {listed!r}"
    mon = _settled_monitor(nm, monitor_name)
    assert (mon["monitorArn"], mon["aggregationPeriod"]) == (out["MonitorRef"], 30), (
        f"GetMonitor reads {(mon['monitorArn'], mon['aggregationPeriod'])!r}"
    )
    mon_tags = _user_tags(nm, mon["monitorArn"])
    assert mon_tags == want_tags, f"monitor tags {mon_tags!r}, expected {want_tags!r}"

    # Probe: composite Ref, the stable GetAtts and every templated property.
    assert len(mon["probes"]) == 1, f"expected exactly one probe in GetMonitor, got {mon['probes']!r}"
    probe = mon["probes"][0]
    source_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:subnet/{out['SubnetId']}"
    got = (out["ProbeRef"], out["ProbeId"], out["ProbeArn"], out["ProbeVpcId"],
           out["ProbeAddressFamily"], probe["vpcId"], probe["sourceArn"], probe["destination"],
           probe["protocol"])
    want = (f"{monitor_name}|{probe['probeId']}", probe["probeId"], probe["probeArn"],
            probe["vpcId"], probe["addressFamily"], out["VpcId"], source_arn, _DESTINATION, "ICMP")
    assert got == want, f"probe reads {got!r}, expected {want!r}"
    fetched = nm.get_probe(monitorName=monitor_name, probeId=probe["probeId"])
    assert (fetched["probeArn"], fetched["state"]) == (probe["probeArn"], "ACTIVE"), (
        f"GetProbe reads {(fetched['probeArn'], fetched['state'])!r}"
    )
    probe_tags = _user_tags(nm, probe["probeArn"])
    assert probe_tags == want_tags, f"probe tags {probe_tags!r}, expected {want_tags!r}"

    # The probe's own delete: an update dropping it leaves the same monitor with no probes,
    # and a monitor without probes reads INACTIVE.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(monitor_name, _DESTINATION, stack, with_probe=False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"probe-removing update ended {status!r}"
    mon = _settled_monitor(nm, monitor_name, "INACTIVE")
    assert (mon["monitorArn"], mon["probes"]) == (out["MonitorRef"], []), (
        f"after dropping the Probe GetMonitor reads {mon!r}"
    )

    delete_stack(cfn, stack_id)
    got = _masked_error(lambda: nm.get_monitor(monitorName=monitor_name), ctx.account)
    want = ("ResourceNotFoundException",
            f"No existing monitor found for account <account> and monitorName {monitor_name}.")
    assert got == want, f"GetMonitor after the delete: {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
