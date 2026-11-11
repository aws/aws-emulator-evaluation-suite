"""deploy-ec2-1-bad-ami-instance-rolls-back-the-network-in-reverse-order."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-1-bad-ami-instance-rolls-back-the-network-in-reverse-order"

GROUP = "deploy-cfn-ec2-network"

SERVICES = ["cloudformation", "ec2"]

VPC_BLOCK = "10.71.0.0/16"
SUBNET_A_BLOCK = "10.71.0.0/24"
SUBNET_B_BLOCK = "10.71.1.0/24"
INSTANCE_TYPE = "t3.micro"
# Well-formed (ami- + 17 hex digits) so the request reaches EC2's image lookup rather than a
# syntax validator, and not an image that exists in any region.
BAD_AMI = "ami-00000000deadbeef0"

# Every resource the stack creates successfully before the instance is attempted.
NETWORK = ["Vpc", "Igw", "Attach", "SubnetA", "SubnetB", "RouteTable", "Route", "Eip", "Sg"]

# child -> the resources it depends on (Ref / GetAtt / DependsOn), i.e. the creation partial
# order. A faithful engine must create a parent before any child starts and, on rollback,
# finish deleting every child before it starts deleting the parent.
EDGES = {
    "Attach": ["Vpc", "Igw"],
    "SubnetA": ["Vpc"],
    "SubnetB": ["Vpc"],
    "RouteTable": ["Vpc"],
    "Sg": ["Vpc"],
    "Route": ["RouteTable", "Igw", "Attach"],
    "Eip": ["Attach"],
}
INSTANCE_EDGES = ["SubnetA", "SubnetB", "Sg", "Eip", "Route"]


def _template(tag: str) -> str:
    t = [{"Key": "sim2real", "Value": tag}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Az": {"Type": "String"}},
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK, "Tags": t}},
            "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": t}},
            "Attach": {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}}},
            "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": SUBNET_A_BLOCK,
                "AvailabilityZone": {"Ref": "Az"}, "Tags": t}},
            "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": SUBNET_B_BLOCK,
                "AvailabilityZone": {"Ref": "Az"}, "Tags": t}},
            "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "Tags": t}},
            "Route": {"Type": "AWS::EC2::Route", "DependsOn": "Attach", "Properties": {
                "RouteTableId": {"Ref": "RouteTable"}, "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": {"Ref": "Igw"}}},
            "Eip": {"Type": "AWS::EC2::EIP", "DependsOn": "Attach", "Properties": {
                "Domain": "vpc", "Tags": t}},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "GroupDescription": "sim2real deploy-ec2-1 rollback", "VpcId": {"Ref": "Vpc"},
                "Tags": t}},
            # The resource designed to fail. It depends on EVERYTHING, so it is attempted only
            # after the whole network is CREATE_COMPLETE and its failure rolls back a complete
            # estate. The EIP allocation id rides in a tag so CloudFormation's own record of
            # the resolved properties carries it even though the stack never produces outputs.
            "Instance": {"Type": "AWS::EC2::Instance", "DependsOn": ["Route", "SubnetB"],
                         "Properties": {
                "ImageId": BAD_AMI, "InstanceType": INSTANCE_TYPE,
                "SubnetId": {"Ref": "SubnetA"}, "SecurityGroupIds": [{"Ref": "Sg"}],
                "Tags": t + [{"Key": "sim2real-eip-alloc",
                              "Value": {"Fn::GetAtt": ["Eip", "AllocationId"]}}]}},
        },
    })


def _stack_events(cfn, stack: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _wait_stack_status(cfn, stack: str, timeout_s: float = 1500.0) -> dict[str, Any]:
    """Poll until the stack leaves every *_IN_PROGRESS status."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        if not last["StackStatus"].endswith("_IN_PROGRESS"):
            return last
        time.sleep(5)
    raise AssertionError(f"stack {stack!r} still in progress after {timeout_s}s: "
                         f"{(last or {}).get('StackStatus')!r}")


def _settle_code(fn, want: str, timeout_s: float = 180.0) -> str:
    """Poll a describe call until it raises `want` (EC2 deletes are eventually consistent)."""
    deadline = time.monotonic() + timeout_s
    code = None
    while time.monotonic() < deadline:
        try:
            fn()
            code = "<call succeeded>"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
        if code == want:
            return code
        time.sleep(5)
    return code


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_id)
        st = _wait_stack_status(cfn, stack_id)
        if st["StackStatus"] != "DELETE_COMPLETE":
            raise RuntimeError(f"stack {stack_id} ended {st['StackStatus']}: "
                               f"{st.get('StackStatusReason')}")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id} delete failed: {exc!r}") from exc


def _usable_az(ec2) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _first(events, lid: str, status: str, reason_prefix: str | None = None):
    for e in events:
        if e.get("LogicalResourceId") == lid and e.get("ResourceStatus") == status:
            if reason_prefix is None or (e.get("ResourceStatusReason") or "").startswith(
                    reason_prefix):
                return e
    return None




@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """An instance with a nonexistent AMI fails the stack after a full VPC network is complete;
    rollback unwinds the network in reverse dependency order until every id answers NotFound in EC2.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)

    name = ctx.unique_name("sim2real-xsvc-ec2rb-")
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=_template(name),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    # 1. the stack as a whole ends ROLLBACK_COMPLETE (not CREATE_COMPLETE, not ROLLBACK_FAILED)
    stack = _wait_stack_status(cfn, stack_id)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a stack whose instance names a nonexistent AMI ended {stack['StackStatus']!r} "
        f"({stack.get('StackStatusReason')!r}), expected 'ROLLBACK_COMPLETE'"
    )
    events = _stack_events(cfn, stack_id)
    trail = [(e.get("LogicalResourceId"), e.get("ResourceStatus")) for e in events]

    # 2. the failure is the instance's, and it names the AMI -- not some other resource's
    failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"]
    assert [e["LogicalResourceId"] for e in failed] == ["Instance"], (
        f"expected exactly the Instance to fail creation; CREATE_FAILED events were "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    assert f"The image id '[{BAD_AMI}]' does not exist" in reason, (
        f"the Instance failure reason was {reason!r}; it must be EC2's image-not-found refusal "
        f"naming {BAD_AMI!r}"
    )

    # 3. positive control: every network resource reached CREATE_COMPLETE before the instance
    #    was even attempted, so the rollback below unwinds real, completed resources
    inst_start = _first(events, "Instance", "CREATE_IN_PROGRESS")
    assert inst_start is not None, f"the Instance was never attempted; events: {trail!r}"
    for lid in NETWORK:
        done = _first(events, lid, "CREATE_COMPLETE")
        assert done is not None, f"{lid} never reached CREATE_COMPLETE; events: {trail!r}"
        assert done["Timestamp"] <= inst_start["Timestamp"], (
            f"{lid} completed at {done['Timestamp'].isoformat()} but the Instance (which depends "
            f"on it) started at {inst_start['Timestamp'].isoformat()}"
        )

    # 4. forward order: no child starts creating before each of its dependencies completed --
    #    in particular Route and Eip never start before the VPCGatewayAttachment completes
    for child, parents in EDGES.items():
        c_start = _first(events, child, "CREATE_IN_PROGRESS")
        for parent in parents:
            p_done = _first(events, parent, "CREATE_COMPLETE")
            assert c_start["Timestamp"] >= p_done["Timestamp"], (
                f"{child} started creating at {c_start['Timestamp'].isoformat()}, before its "
                f"dependency {parent} completed at {p_done['Timestamp'].isoformat()}"
            )

    # 5. the rollback is a deletion of what succeeded, and only begins after the failure
    rb = _first(events, name, "ROLLBACK_IN_PROGRESS")
    assert rb is not None and rb["Timestamp"] >= failed[0]["Timestamp"], (
        f"no ROLLBACK_IN_PROGRESS after the instance failure; events: {trail!r}"
    )
    for lid in NETWORK:
        d_start = _first(events, lid, "DELETE_IN_PROGRESS")
        d_done = _first(events, lid, "DELETE_COMPLETE")
        assert d_start is not None and d_done is not None, (
            f"{lid} was not deleted by the rollback; events: {trail!r}"
        )
        assert d_start["Timestamp"] >= rb["Timestamp"], (
            f"{lid} began deleting at {d_start['Timestamp'].isoformat()}, before the rollback "
            f"started at {rb['Timestamp'].isoformat()}"
        )

    # 6. reverse order: every child is fully deleted before deletion of its dependency begins
    for child, parents in EDGES.items():
        c_gone = _first(events, child, "DELETE_COMPLETE")
        for parent in parents:
            p_start = _first(events, parent, "DELETE_IN_PROGRESS")
            assert p_start["Timestamp"] >= c_gone["Timestamp"], (
                f"rollback began deleting {parent} at {p_start['Timestamp'].isoformat()} while its "
                f"dependent {child} was not deleted until {c_gone['Timestamp'].isoformat()}"
            )
    # and a root of the graph is the last network resource to go: Vpc and Igw share no edge, so
    # either may finish last
    last_gone = max(NETWORK, key=lambda lid: _first(events, lid, "DELETE_COMPLETE")["Timestamp"])
    assert last_gone in ("Vpc", "Igw"), (
        f"the last resource the rollback deleted was {last_gone!r}; a root (Vpc or Igw) that no "
        f"remaining resource depends on must be deleted last"
    )

    # 7. effect-absent, in EC2's own records: every physical id answers its type's NotFound
    phys = {lid: (_first(events, lid, "CREATE_COMPLETE") or {}).get("PhysicalResourceId")
            for lid in NETWORK}
    props = json.loads(inst_start.get("ResourceProperties") or "{}")
    alloc = {t["Key"]: t["Value"] for t in props.get("Tags", [])}.get("sim2real-eip-alloc")
    assert alloc and alloc.startswith("eipalloc-"), (
        f"CloudFormation's record of the Instance properties carried EIP allocation id "
        f"{alloc!r}; expected an 'eipalloc-' id resolved from Fn::GetAtt Eip.AllocationId"
    )
    probes = [
        ("Vpc", lambda: ec2.describe_vpcs(VpcIds=[phys["Vpc"]]), "InvalidVpcID.NotFound"),
        ("SubnetA", lambda: ec2.describe_subnets(SubnetIds=[phys["SubnetA"]]),
         "InvalidSubnetID.NotFound"),
        ("SubnetB", lambda: ec2.describe_subnets(SubnetIds=[phys["SubnetB"]]),
         "InvalidSubnetID.NotFound"),
        ("Sg", lambda: ec2.describe_security_groups(GroupIds=[phys["Sg"]]),
         "InvalidGroup.NotFound"),
        ("Igw", lambda: ec2.describe_internet_gateways(InternetGatewayIds=[phys["Igw"]]),
         "InvalidInternetGatewayID.NotFound"),
        ("RouteTable", lambda: ec2.describe_route_tables(RouteTableIds=[phys["RouteTable"]]),
         "InvalidRouteTableID.NotFound"),
        ("Eip", lambda: ec2.describe_addresses(AllocationIds=[alloc]),
         "InvalidAllocationID.NotFound"),
    ]
    for lid, fn, want in probes:
        got = _settle_code(fn, want)
        assert got == want, (
            f"after ROLLBACK_COMPLETE the rolled-back {lid} ({phys.get(lid) or alloc!r}) answers "
            f"{got!r}, expected {want!r}"
        )

    # 8. the EIP is released, not merely detached: no address carries this stack's tag
    tagged = ec2.describe_addresses(
        Filters=[{"Name": "tag:sim2real", "Values": [name]}])["Addresses"]
    assert tagged == [], f"addresses still tagged for this stack after rollback: {tagged!r}"

    # 9. the failing instance never came into existence at all
    leaked = [i["InstanceId"] for r in ec2.describe_instances(
        Filters=[{"Name": "tag:sim2real", "Values": [name]}])["Reservations"]
        for i in r["Instances"]]
    assert leaked == [], f"instances exist for a stack whose AMI does not exist: {leaked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
