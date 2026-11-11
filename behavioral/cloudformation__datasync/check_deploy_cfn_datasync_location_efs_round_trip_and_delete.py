"""deploy-cfn-datasync-location-efs-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-datasync-location-efs-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "datasync"]

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

_VPC_CIDR = "10.112.0.0/16"
_SUBNET_CIDR = "10.112.1.0/24"


def _template(az: str, vpc_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": _VPC_CIDR, "Tags": [{"Key": "Name", "Value": vpc_name}],
            }},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                                "AvailabilityZone": az},
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real datasync efs location check",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupIngress": [{
                        "IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049, "CidrIp": _VPC_CIDR,
                    }],
                },
            },
            "Fs": {"Type": "AWS::EFS::FileSystem"},
            "Mt": {
                "Type": "AWS::EFS::MountTarget",
                "Properties": {"FileSystemId": {"Ref": "Fs"}, "SubnetId": {"Ref": "Subnet"},
                                "SecurityGroups": [{"Ref": "Sg"}]},
            },
            "Loc": {
                "Type": "AWS::DataSync::LocationEFS",
                "Properties": {
                    "EfsFilesystemArn": {"Fn::GetAtt": ["Fs", "Arn"]},
                    "Ec2Config": {
                        "SubnetArn": {"Fn::Sub":
                            "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:subnet/${Subnet}"},
                        "SecurityGroupArns": [{"Fn::Sub":
                            "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/${Sg}"}],
                    },
                },
                "DependsOn": "Mt",
            },
        },
        "Outputs": {
            "SubnetArn": {"Value": {"Fn::Sub":
                "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:subnet/${Subnet}"}},
            "SgArn": {"Value": {"Fn::Sub":
                "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/${Sg}"}},
            "FsArn": {"Value": {"Fn::GetAtt": ["Fs", "Arn"]}},
            "LocArn": {"Value": {"Ref": "Loc"}},
            "LocUri": {"Value": {"Fn::GetAtt": ["Loc", "LocationUri"]}},
        },
    })


def _usable_az(ec2) -> str:
    """The first available AZ in this region, by name."""
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    names = sorted(z["ZoneName"] for z in zones)
    assert names, "no available availability zone in this region"
    return names[0]


def _location_arns_for_uri(ds, uri: str) -> list[str]:
    """Every listed location ARN whose LocationUri is ``uri``, read across all pages."""
    return [loc["LocationArn"]
            for page in ds.get_paginator("list_locations").paginate()
            for loc in page["Locations"] if loc["LocationUri"] == uri]


def _assert_location_ref(ctx, ds, loc_arn: str, uri: str) -> None:
    """Ref is a documented location ARN, and ListLocations lists exactly it for ``uri``."""
    pattern = (rf"arn:aws[a-z-]*:datasync:{re.escape(ctx.region)}:{ctx.account}:"
               r"location/loc-[0-9a-f]{17}")
    assert re.fullmatch(pattern, loc_arn), (
        f"Ref Loc {loc_arn!r} is not a DataSync location ARN in this account and region"
    )
    listed = _location_arns_for_uri(ds, uri)
    assert listed == [loc_arn], (
        f"expected ListLocations to hold exactly Ref Loc for {uri!r}, got {listed!r}"
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DataSync::LocationEFS reads back through DataSync's own
    DescribeLocationEfs with the template's subnet, security group and file system;
    deleting the stack removes it, and DataSync then refuses to describe it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-datasync-locationefs.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    ds = ctx.client("datasync")

    stack = ctx.unique_name("sim2real-ds-efs-")
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(az, stack))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    loc_arn = outputs["LocArn"]
    fs_arn = outputs["FsArn"]
    fs_id = fs_arn.rsplit("/", 1)[-1]

    want_uri = f"efs://{ctx.region}.{fs_id}/"
    _assert_location_ref(ctx, ds, loc_arn, want_uri)
    loc = ds.describe_location_efs(LocationArn=loc_arn)
    assert loc["Ec2Config"]["SubnetArn"] == outputs["SubnetArn"], (
        f"expected Ec2Config.SubnetArn {outputs['SubnetArn']!r}, "
        f"DescribeLocationEfs reports {loc['Ec2Config']['SubnetArn']!r}"
    )
    assert loc["Ec2Config"]["SecurityGroupArns"] == [outputs["SgArn"]], (
        f"expected Ec2Config.SecurityGroupArns {[outputs['SgArn']]!r}, "
        f"DescribeLocationEfs reports {loc['Ec2Config']['SecurityGroupArns']!r}"
    )
    assert loc["LocationUri"] == outputs["LocUri"], (
        f"expected Fn::GetAtt Loc.LocationUri to match DescribeLocationEfs LocationUri "
        f"{loc['LocationUri']!r}, got {outputs['LocUri']!r}"
    )
    assert loc["LocationUri"] == want_uri, (
        f"expected LocationUri to name file system {fs_id!r} ({want_uri!r}), got {loc['LocationUri']!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    location_gone = ("InvalidRequestException", f"Location {loc_arn} is not found.")
    expect_error(lambda: ds.describe_location_efs(LocationArn=loc_arn), *location_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
