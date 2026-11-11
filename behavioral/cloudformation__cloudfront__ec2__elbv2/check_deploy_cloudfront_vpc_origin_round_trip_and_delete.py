"""deploy-cloudfront-vpc-origin-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-vpc-origin-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront", "ec2", "elbv2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
# The VPC origin delete waits on CloudFront's edge for about ten minutes; one stack fits the
# suite's 1800 s cleanup budget.
_DELETE_BUDGET_S = 900.0


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

# A VPC origin deploys to CloudFront's edge before CREATE_COMPLETE, and its delete waits on the
# edge too: the create gets what the run deadline leaves after the delete's budget, so both fit
# under the suite's 1800 s check budget.
_RUN_BUDGET_S = 1740.0


def _template(vpc_origin_name: str) -> str:
    """Stack tags propagate to the EC2 and ELB resources; the origin carries its own tag too."""
    return json.dumps({
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.93.0.0/16"}},
            "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
            "IgwAttachment": {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}}},
            "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.93.1.0/24",
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}}},
            "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.93.2.0/24",
                "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]}}},
            "AlbSg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "GroupDescription": CHECK, "VpcId": {"Ref": "Vpc"}}},
            "Alb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {
                "Type": "application", "Scheme": "internal",
                "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                "SecurityGroups": [{"Ref": "AlbSg"}]}},
            "VpcOrigin": {"Type": "AWS::CloudFront::VpcOrigin", "DependsOn": ["IgwAttachment"],
                          "Properties": {
                              "VpcOriginEndpointConfig": {
                                  "Name": vpc_origin_name, "Arn": {"Ref": "Alb"},
                                  "HTTPPort": 80, "HTTPSPort": 443,
                                  "OriginProtocolPolicy": "http-only"},
                              "Tags": [{"Key": "sim2real-vo", "Value": vpc_origin_name}],
                          }},
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "AlbArn": {"Value": {"Ref": "Alb"}},
            "AlbSgId": {"Value": {"Ref": "AlbSg"}},
            "SubnetIds": {"Value": {"Fn::Join": [",", [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]]}},
            "SubnetAId": {"Value": {"Ref": "SubnetA"}},
            "SubnetBId": {"Value": {"Ref": "SubnetB"}},
            "AzA": {"Value": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}},
            "AzB": {"Value": {"Fn::Select": [1, {"Fn::GetAZs": ""}]}},
            "VpcOriginId": {"Value": {"Ref": "VpcOrigin"}},
            "VpcOriginArn": {"Value": {"Fn::GetAtt": ["VpcOrigin", "Arn"]}},
        },
    })


def _vpc_origins(cf):
    """Every VPC origin, across every Marker page."""
    items, marker = [], None
    while True:
        page = cf.list_vpc_origins(**({"Marker": marker} if marker else {}))["VpcOriginList"]
        items += page.get("Items", [])
        marker = page.get("NextMarker")
        if not marker:
            return items


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CloudFront::VpcOrigin backed by an internal ALB reads back, then is deleted.

    Ref and the Arn GetAtt match the ListVpcOrigins entry, every templated property reads back
    through CloudFront, ELBv2 and EC2, and the stack delete removes the origin, ALB and VPC.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    stack = ctx.unique_name("sim2real-cf-vpcorigin-")
    vpc_origin_name = ctx.unique_name("sim2real-cf-vpcorigin-")

    deadline = time.monotonic() + _RUN_BUDGET_S
    stack_id = create_stack(ctx, cfn, stack, _template(vpc_origin_name))
    status = wait_stack(cfn, stack_id, timeout_s=deadline - time.monotonic() - _DELETE_BUDGET_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    vo_id, vo_arn, alb_arn, vpc_id = (out["VpcOriginId"], out["VpcOriginArn"], out["AlbArn"],
                                      out["VpcId"])

    listed = [(v["Id"], v["Arn"]) for v in _vpc_origins(cf) if v["Name"] == vpc_origin_name]
    assert listed == [(vo_id, vo_arn)], f"ListVpcOrigins named {vpc_origin_name!r}: {listed!r}"
    config = cf.get_vpc_origin(Id=vo_id)["VpcOrigin"]["VpcOriginEndpointConfig"]
    got = (config["Name"], config["Arn"], config["HTTPPort"], config["HTTPSPort"],
           config["OriginProtocolPolicy"])
    assert got == (vpc_origin_name, alb_arn, 80, 443, "http-only"), f"VPC origin config {got!r}"
    tag_list = cf.list_tags_for_resource(Resource=vo_arn)["Tags"]["Items"]
    tag_values = {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}
    assert tag_values == {"sim2real": stack, "sim2real-vo": vpc_origin_name}, f"tags {tag_values!r}"

    alb = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"]
    got = [(a["Type"], a["Scheme"], a["VpcId"], sorted(z["SubnetId"] for z in a["AvailabilityZones"]),
            a["SecurityGroups"]) for a in alb]
    want = [("application", "internal", vpc_id, sorted(out["SubnetIds"].split(",")),
             [out["AlbSgId"]])]
    assert got == want, f"DescribeLoadBalancers {got!r}, expected {want!r}"
    vpcs = [v["CidrBlock"] for v in ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]]
    assert vpcs == ["10.93.0.0/16"], f"DescribeVpcs {vpcs!r}"
    subnets = sorted((s["SubnetId"], s["VpcId"], s["CidrBlock"], s["AvailabilityZone"])
                     for s in ec2.describe_subnets(SubnetIds=out["SubnetIds"].split(","))["Subnets"])
    want = sorted([(out["SubnetAId"], vpc_id, "10.93.1.0/24", out["AzA"]),
                   (out["SubnetBId"], vpc_id, "10.93.2.0/24", out["AzB"])])
    assert subnets == want, f"DescribeSubnets {subnets!r}, expected {want!r}"
    groups = [(g["Description"], g["VpcId"])
              for g in ec2.describe_security_groups(GroupIds=[out["AlbSgId"]])["SecurityGroups"]]
    assert groups == [(CHECK, vpc_id)], f"DescribeSecurityGroups {groups!r}"

    delete_stack(cfn, stack_id)
    vpc_origin_gone = ("EntityNotFound", "The specified vpc origin does not exist")
    expect_error(lambda: cf.get_vpc_origin(Id=vo_id), *vpc_origin_gone)
    load_balancers_gone = ("LoadBalancerNotFound", "One or more load balancers not found")
    expect_error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn]),
                 *load_balancers_gone)
    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpcs_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
