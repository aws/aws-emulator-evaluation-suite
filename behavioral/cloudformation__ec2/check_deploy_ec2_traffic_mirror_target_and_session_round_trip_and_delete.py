"""deploy-ec2-traffic-mirror-target-and-session-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-traffic-mirror-target-and-session-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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

INSTANCE_TYPE = "m5.large"  # a Nitro type: a mirror source must be on a Nitro instance
AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.123.0.0/16"
_SUBNET_CIDR = "10.123.1.0/24"
_SESSION_NUMBER = 1


def _template(name, with_session=True):
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
            "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
        }},
        "Group": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "sim2real traffic mirror session group", "VpcId": {"Ref": "Vpc"},
        }},
        "SourceEni": {"Type": "AWS::EC2::NetworkInterface", "Properties": {
            "SubnetId": {"Ref": "Subnet"}, "GroupSet": [{"Ref": "Group"}]}},
        "TargetEni": {"Type": "AWS::EC2::NetworkInterface", "Properties": {
            "SubnetId": {"Ref": "Subnet"}, "GroupSet": [{"Ref": "Group"}]}},
        "Instance": {"Type": "AWS::EC2::Instance", "Properties": {
            "ImageId": {"Ref": "Ami"},
            "InstanceType": INSTANCE_TYPE,
            "NetworkInterfaces": [
                {"DeviceIndex": "0", "NetworkInterfaceId": {"Ref": "SourceEni"}},
                {"DeviceIndex": "1", "NetworkInterfaceId": {"Ref": "TargetEni"}},
            ],
        }},
        "Filter": {"Type": "AWS::EC2::TrafficMirrorFilter", "Properties": {
            "Description": "sim2real traffic mirror session filter"}},
        "Target": {"Type": "AWS::EC2::TrafficMirrorTarget", "DependsOn": "Instance",
                   "Properties": {"NetworkInterfaceId": {"Ref": "TargetEni"},
                                  "Description": "sim2real traffic mirror session target",
                                  "Tags": [{"Key": "sim2real-tmt", "Value": name}]}},
    }
    outputs = {k: {"Value": {"Ref": k}} for k in
               ("Instance", "SourceEni", "TargetEni", "Filter", "Target")}
    if with_session:
        resources["Session"] = {"Type": "AWS::EC2::TrafficMirrorSession", "Properties": {
            "NetworkInterfaceId": {"Ref": "SourceEni"},
            "TrafficMirrorTargetId": {"Ref": "Target"},
            "TrafficMirrorFilterId": {"Ref": "Filter"},
            "SessionNumber": _SESSION_NUMBER,
            "Description": "sim2real traffic mirror session",
            "Tags": [{"Key": "sim2real-tms", "Value": name}],
        }}
        outputs["Session"] = {"Value": {"Ref": "Session"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Ami": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                               "Default": AMI_PARAMETER}},
        "Resources": resources,
        "Outputs": outputs,
    })


def _own_tags(resource):
    return {t["Key"]: t["Value"] for t in resource.get("Tags", [])
            if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrafficMirrorTarget and TrafficMirrorSession, with the session's source ENI
    on a running instance, read back through EC2 by the stack tag; an update dropping the session
    removes it while the target answers, and deleting the stack removes the target.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2tmts-")
    by_tag = [{"Name": "tag:sim2real", "Values": [stack]}]

    stack_id = create_stack(ctx, cfn, stack, _template(stack))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[out["Instance"]], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    targets = paginate(ec2, "describe_traffic_mirror_targets", "TrafficMirrorTargets",
                       Filters=by_tag)
    got = [(t["TrafficMirrorTargetId"], t["NetworkInterfaceId"], t["Description"], _own_tags(t))
           for t in targets]
    assert got == [(out["Target"], out["TargetEni"], "sim2real traffic mirror session target",
                    {"sim2real": stack, "sim2real-tmt": stack})], f"targets by stack tag {got!r}"
    sessions = paginate(ec2, "describe_traffic_mirror_sessions", "TrafficMirrorSessions",
                        Filters=by_tag)
    got = [(s["TrafficMirrorSessionId"], s["NetworkInterfaceId"], s["TrafficMirrorTargetId"],
            s["TrafficMirrorFilterId"], s["SessionNumber"], s["Description"], _own_tags(s))
           for s in sessions]
    want = [(out["Session"], out["SourceEni"], out["Target"], out["Filter"], _SESSION_NUMBER,
             "sim2real traffic mirror session", {"sim2real": stack, "sim2real-tms": stack})]
    assert got == want, f"sessions by stack tag {got!r}, expected {want!r}"

    # The session's own delete: an update drops it while the same target still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"session-removing update ended {status!r}"
    refused = ("InvalidTrafficMirrorSessionId.NotFound", f"{out['Session']} does not exist")
    expect_error(
        lambda: ec2.describe_traffic_mirror_sessions(
        TrafficMirrorSessionIds=[out["Session"]]),
        *refused,
    )
    still = paginate(ec2, "describe_traffic_mirror_targets", "TrafficMirrorTargets",
                     TrafficMirrorTargetIds=[out["Target"]])
    assert [t["TrafficMirrorTargetId"] for t in still] == [out["Target"]], "target gone too"

    delete_stack(cfn, stack_id)
    refused = ("InvalidTrafficMirrorTargetId.NotFound", f"{out['Target']} does not exist")
    expect_error(
        lambda: ec2.describe_traffic_mirror_targets(
        TrafficMirrorTargetIds=[out["Target"]]),
        *refused,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
