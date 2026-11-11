"""deploy-networkmonitor-probe-invalid-destination-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-networkmonitor-probe-invalid-destination-rejected-and-rolled-back"
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


_VPC_CIDR = "10.99.0.0/16"
_SUBNET_CIDR = "10.99.1.0/24"
_BAD_DESTINATION = "example.com"
_GOOD_DESTINATION = "10.99.1.10"
_REJECTED = (
    f"destination must be a valid IPv4 or IPv6 address: [{_BAD_DESTINATION}] (Service: "
    "NetworkMonitor; Operation: CreateProbe; Status Code: 400; Error Code: ValidationException; "
    "Request ID: <id>)",
    "InvalidRequest",
)


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


def _active_monitor(nm, name: str) -> dict:
    """GetMonitor polled (bounded) until the monitor and every probe are ACTIVE."""
    deadline = time.monotonic() + 300
    while True:
        mon = nm.get_monitor(monitorName=name)
        if mon["state"] == "ACTIVE" and all(p["state"] == "ACTIVE" for p in mon["probes"]):
            return mon
        if time.monotonic() > deadline:
            raise AssertionError(f"monitor {name!r} not ACTIVE after 300s: {mon!r}")
        time.sleep(3)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation NetworkMonitor Probe with a domain-name Destination is refused.

    The handler relays NetworkMonitor's exact reason and the rollback removes the Monitor it had
    created, while the same template with a literal address deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    nm = ctx.client("networkmonitor")

    bad_stack = ctx.unique_name("sim2real-nmcfnbad-")
    bad_id = create_stack(ctx, cfn, bad_stack, _template(bad_stack, _BAD_DESTINATION, bad_stack))
    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Probe"), ctx.account, bad_stack)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # The rollback removed the Monitor it had created, before this check's own delete.
    got = _masked_error(lambda: nm.get_monitor(monitorName=bad_stack), ctx.account)
    want = ("ResourceNotFoundException",
            f"No existing monitor found for account <account> and monitorName {bad_stack}.")
    assert got == want, f"GetMonitor after the rollback: {got!r}, expected {want!r}"

    # Positive control: the same template with only Destination a literal address.
    good_stack = ctx.unique_name("sim2real-nmcfngood-")
    good_id = create_stack(ctx, cfn, good_stack,
                           _template(good_stack, _GOOD_DESTINATION, good_stack))
    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"positive control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    partition = good_id.split(":")[1]
    mon = _active_monitor(nm, good_stack)
    assert (mon["monitorArn"], mon["aggregationPeriod"]) == (out["MonitorRef"], 30), (
        f"control monitor reads {(mon['monitorArn'], mon['aggregationPeriod'])!r}"
    )
    source_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:subnet/{out['SubnetId']}"
    got = [(p["destination"], p["protocol"], p["sourceArn"], p["state"]) for p in mon["probes"]]
    assert got == [(_GOOD_DESTINATION, "ICMP", source_arn, "ACTIVE")], f"control probes {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
