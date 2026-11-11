"""deploy-ec2-vpc-endpoint-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-vpc-endpoint-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
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

_VPC_CIDR = "10.100.0.0/16"


def _template(tag_value: str, region: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    service_name = f"com.amazonaws.{region}.s3"
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": t},
            },
            "Endpoint": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "ServiceName": service_name,
                    "VpcEndpointType": "Gateway",
                    "RouteTableIds": [{"Ref": "RouteTable"}],
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "RouteTableId": {"Value": {"Ref": "RouteTable"}},
            "EndpointId": {"Value": {"Ref": "Endpoint"}},
            "EndpointGetAttId": {"Value": {"Fn::GetAtt": ["Endpoint", "Id"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Gateway AWS::EC2::VPCEndpoint to S3 reads back through EC2 with the declared
    ServiceName, type and route table, which routes S3's prefix list through it; deleting the
    stack removes the endpoint, which EC2 then refuses by id.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcendpoint.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2vpce-")

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK, ctx.region))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    vpc_id, rt_id, endpoint_id = outputs["VpcId"], outputs["RouteTableId"], outputs["EndpointId"]
    want_service = f"com.amazonaws.{ctx.region}.s3"

    endpoints = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
    assert endpoints, f"DescribeVpcEndpoints({endpoint_id!r}) returned nothing"
    ep = endpoints[0]
    got_ids = (endpoint_id, outputs["EndpointGetAttId"])
    assert got_ids == (ep["VpcEndpointId"],) * 2, (
        f"(Ref Endpoint, GetAtt Endpoint.Id) {got_ids!r}, EC2 reports {ep['VpcEndpointId']!r}"
    )
    assert ep["ServiceName"] == want_service, (
        f"expected ServiceName {want_service!r}, EC2 reports {ep['ServiceName']!r}"
    )
    assert ep["VpcEndpointType"] == "Gateway", (
        f"expected VpcEndpointType 'Gateway', EC2 reports {ep['VpcEndpointType']!r}"
    )
    assert ep["VpcId"] == vpc_id, (
        f"expected the endpoint's VpcId to be {vpc_id!r}, EC2 reports {ep['VpcId']!r}"
    )
    assert ep["RouteTableIds"] == [rt_id], (
        f"expected RouteTableIds {[rt_id]!r}, EC2 reports {ep['RouteTableIds']!r}"
    )
    assert ep["State"] == "available", (
        f"expected State 'available' once CREATE_COMPLETE, EC2 reports {ep['State']!r}"
    )

    # A Gateway endpoint routes the service's prefix list through itself in each route table.
    prefix_lists = ec2.describe_prefix_lists(
        Filters=[{"Name": "prefix-list-name", "Values": [want_service]}])["PrefixLists"]
    pl_ids = [p["PrefixListId"] for p in prefix_lists]
    assert len(pl_ids) == 1, (
        f"expected one prefix list named {want_service!r}, EC2 reports {pl_ids!r}"
    )
    routes = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    pl_routes = [(r.get("DestinationPrefixListId"), r.get("GatewayId")) for r in routes
                 if "DestinationPrefixListId" in r]
    assert pl_routes == [(pl_ids[0], endpoint_id)], (
        f"expected route table {rt_id!r} to route prefix list {pl_ids[0]!r} through "
        f"{endpoint_id!r}, EC2 reports {pl_routes!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    vpc_endpoints_gone = (
        "InvalidVpcEndpointId.NotFound",
        f"The Vpc Endpoint Id '{endpoint_id}' does not exist",
    )
    expect_error(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id]),
        *vpc_endpoints_gone,
    )

    route_tables_gone = (
        "InvalidRouteTableID.NotFound",
        f"The routeTable ID '{rt_id}' does not exist",
    )
    expect_error(lambda: ec2.describe_route_tables(RouteTableIds=[rt_id]), *route_tables_gone)

    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpcs_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
