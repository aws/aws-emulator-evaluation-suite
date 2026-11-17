"""deploy-ec2-instance-connect-endpoint-invalid-subnet-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-instance-connect-endpoint-invalid-subnet-rejected-and-rolled-back"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``."""
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=600.0):
    """Poll DescribeStacks by StackId every 5 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(5)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns."""
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name>; cleanup registered before the call."""
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
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
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


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except the named not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def poll(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ---- Check-specific: the templates, then run(). ----

_BAD_SUBNET = "subnet-00000000000000000"
# The handler reason; the Request ID and SDK Attempt Count vary per call and are masked.
_REJECTED = (
    f"The subnet ID '{_BAD_SUBNET}' does not exist (Service: Ec2, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "NotFound",
)


def _bad_template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Endpoint": {
                    "Type": "AWS::EC2::InstanceConnectEndpoint",
                    "Properties": {"SubnetId": _BAD_SUBNET},
                },
            },
        }
    )


def _good_template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"SubnetId": {"Type": "AWS::EC2::Subnet::Id"}},
            "Resources": {
                "Endpoint": {
                    "Type": "AWS::EC2::InstanceConnectEndpoint",
                    "Properties": {"SubnetId": {"Ref": "SubnetId"}},
                },
            },
            "Outputs": {"EndpointId": {"Value": {"Ref": "Endpoint"}}},
        }
    )


def _available_zone(ec2) -> str:
    """The lexically-first AZ this region reports available right now."""
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert zones, "no available availability zone in this region"
    return zones[0]


def _network(ctx, ec2):
    """A VPC with one subnet, each deleted in teardown (LIFO: after the stack that uses it)."""
    name = ctx.unique_name("sim2real-ec2icenet-")
    tag = [{"Key": "Name", "Value": name}]
    zone = _available_zone(ec2)
    vpc = ec2.create_vpc(
        CidrBlock="10.198.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc), "InvalidVpcID.NotFound"))
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.198.1.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_subnet(SubnetId=subnet), "InvalidSubnetID.NotFound")
    )
    return vpc, subnet


# Instance Connect endpoints have a low per-Region quota, so parallel runs of endpoint checks
# in one account can collide.
@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::InstanceConnectEndpoint naming a subnet id that does not exist
    fails with EC2's exact error and rolls the stack back; the same template naming a real subnet
    deploys an endpoint EC2 reads back by that subnet."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")

    bad_stack = ctx.unique_name("sim2real-ec2icebad-")
    bad_stack_id = create_stack(ctx, cfn, bad_stack, _bad_template())
    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )
    got_error = handler_reason(
        failed_reason(stack_events(cfn, bad_stack_id), "Endpoint"), ctx.account
    )
    assert got_error == _REJECTED, (
        f"CREATE_FAILED reason: expected {_REJECTED!r}, got {got_error!r}"
    )
    delete_stack(cfn, bad_stack_id)

    # Positive control: the legal neighbour of a nonexistent subnet — the identical resource
    # naming a real one — deploys.
    vpc_id, subnet_id = _network(ctx, ec2)
    good_stack = ctx.unique_name("sim2real-ec2icegood-")
    good_stack_id = create_stack(
        ctx,
        cfn,
        good_stack,
        _good_template(),
        Parameters=[{"ParameterKey": "SubnetId", "ParameterValue": subnet_id}],
    )
    good_status = wait_stack(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    endpoint_id = stack_outputs(cfn, good_stack_id)["EndpointId"]
    endpoints = poll(
        lambda: ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ],
        lambda eps: eps and eps[0]["State"] == "create-complete",
        timeout_s=300.0,
        description=f"endpoint {endpoint_id} create-complete",
    )
    assert endpoints[0]["SubnetId"] == subnet_id, (
        f"expected SubnetId {subnet_id!r}, EC2 reports {endpoints[0]['SubnetId']!r}"
    )
    assert endpoints[0]["VpcId"] == vpc_id, (
        f"expected VpcId {vpc_id!r}, EC2 reports {endpoints[0]['VpcId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
