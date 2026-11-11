"""network-connector-dualstack-network-protocol-persists."""
from __future__ import annotations

import ipaddress
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-dualstack-network-protocol-persists"
GROUP = "control-plane"
SERVICES = ["lambda-core"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A connector created with NetworkProtocol=DualStack persists that value distinctly from the IPv4 default."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    subnet_id, sg_id = _dualstack_network(ctx)
    role_arn = _operator_role(ctx)
    created = _create_connector(
        lc,
        Name=name,
        Configuration={
            "VpcEgressConfiguration": {
                "SubnetIds": [subnet_id],
                "SecurityGroupIds": [sg_id],
                "NetworkProtocol": "DualStack",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        },
        OperatorRole=role_arn,
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_and_wait_gone(lc, connector_id))

    actual_created = created["Configuration"]["VpcEgressConfiguration"]["NetworkProtocol"]
    assert actual_created == "DualStack", (
        f"CreateNetworkConnector echoed NetworkProtocol={actual_created!r}, expected 'DualStack'"
    )

    fetched = lc.get_network_connector(Identifier=connector_id)
    actual_fetched = fetched["Configuration"]["VpcEgressConfiguration"]["NetworkProtocol"]
    assert actual_fetched == "DualStack", (
        f"DualStack NetworkProtocol did not persist across a GetNetworkConnector round-trip, "
        f"got {actual_fetched!r}"
    )

    ready = _poll_until(
        lambda: lc.get_network_connector(Identifier=connector_id),
        lambda r: r["State"] != "PENDING",
        timeout_s=600,
        interval_s=10,
    )
    assert ready["State"] == "ACTIVE", (
        f"DualStack connector settled as {ready['State']!r} (reason {ready.get('StateReason')!r}), expected ACTIVE"
    )
    settled = ready["Configuration"]["VpcEgressConfiguration"]["NetworkProtocol"]
    assert settled == "DualStack", f"the ACTIVE connector serves NetworkProtocol={settled!r}, expected 'DualStack'"

    # The connector's ENIs block the VPC teardown, so it is deleted and confirmed gone here.
    _delete_and_wait_gone(lc, connector_id)


def _delete_and_wait_gone(lc, connector_id, timeout_s=600):
    """Delete, retrying the state-gated ResourceConflictException, then poll Get until 404."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lc.delete_network_connector(Identifier=connector_id)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        try:
            lc.get_network_connector(Identifier=connector_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"connector {connector_id!r} still answers Get after {timeout_s}s")


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _usable_zone(ec2):
    """The first available zone in the region, the same choice the suite's ACTIVE-reaching checks make."""
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )[
            "AvailabilityZones"
        ]
    )
    assert zones, "region reports no available AvailabilityZones"
    return zones[0]


def _dualstack_network(ctx):
    """Create a fresh VPC/subnet with an IPv6 CIDR association and a security group."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lnc-v6-")
    az = _usable_zone(ec2)

    vpc_id = ec2.create_vpc(CidrBlock="10.202.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ec2.associate_vpc_cidr_block(VpcId=vpc_id, AmazonProvidedIpv6CidrBlock=True)

    def _vpc_ipv6_cidr():
        v = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        for assoc in v.get("Ipv6CidrBlockAssociationSet", []):
            if assoc["Ipv6CidrBlockState"]["State"] == "associated":
                return assoc["Ipv6CidrBlock"]
        return None

    vpc_ipv6_cidr = _poll_until(_vpc_ipv6_cidr, lambda v: v is not None, timeout_s=60, interval_s=3)
    subnet_ipv6_cidr = str(next(ipaddress.ip_network(vpc_ipv6_cidr).subnets(new_prefix=64)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.202.1.0/24",
        Ipv6CidrBlock=subnet_ipv6_cidr,
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", name)],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    def _subnet_ipv6_ready():
        s = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
        for assoc in s.get("Ipv6CidrBlockAssociationSet", []):
            if assoc["Ipv6CidrBlockState"]["State"] == "associated":
                return True
        return False

    _poll_until(_subnet_ipv6_ready, lambda ok: ok, timeout_s=60, interval_s=3)

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda-core dualstack test",
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    return subnet_id, sg_id


OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"
_ROLE_PROPAGATION_WAIT_S = 120.0
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
_UNAUTHORIZED_MESSAGE = (
    "Encountered unauthorized operation while calling EC2 due to invalid "
    "ConnectorOperatorRole permissions"
)


def _operator_role(ctx):
    """Create an IAM role with AWSLambdaNetworkConnectorOperatorPolicy attached, usable as OperatorRole."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lnc-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "Name", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    _poll_until(_attached, lambda ok: ok, timeout_s=30, interval_s=2)
    return role_arn


def _create_connector(lc, **kwargs):
    """EC2's authorization of the operator role's permissions lags IAM policy-attachment propagation
    with no pollable condition; the bounded retry on the exact refusal message is what makes this
    correct, not a fixed sleep."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Message") not in (_UNAUTHORIZED_MESSAGE, _UNASSUMABLE) or time.monotonic() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
