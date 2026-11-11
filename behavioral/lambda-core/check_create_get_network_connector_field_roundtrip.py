"""create-get-network-connector-field-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-get-network-connector-field-roundtrip"
GROUP = "control-plane"
SERVICES = ["lambda-core"]

# Right after CreateRole, CreateNetworkConnector can reject the
# fresh role at TWO successive IAM-propagation gates — "unable to assume the provided
# NetworkConnectorOperatorRole" (trust policy not yet visible) and, once that clears, "invalid
# ConnectorOperatorRole permissions". A PENDING connector also cannot be deleted at all
# (ResourceConflictException) until it leaves PENDING (~250s later).
_ROLE_PROPAGATION_WAIT_S = 120.0
_LEAVES_PENDING_WAIT_S = 600.0
_GONE_WAIT_S = 180.0
_TRANSIENT_ROLE_MESSAGES = (
    "unable to assume the provided NetworkConnectorOperatorRole",
    "invalid ConnectorOperatorRole permissions",
)

_TRUST_LAMBDA = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkConnector's response and a subsequent GetNetworkConnector agree on identity/config fields."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-lnc-")
    subnet_id, sg_id = _build_network(ctx, ec2, name)
    role_arn = _operator_role(ctx, iam, name)

    created = _create_connector(
        lc,
        Name=name,
        Configuration={
            "VpcEgressConfiguration": {
                "SubnetIds": [subnet_id],
                "SecurityGroupIds": [sg_id],
                "NetworkProtocol": "IPv4",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        },
        OperatorRole=role_arn,
        Tags={"sim2real": name},
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))

    assert created["Name"] == name, f"Create echoed Name {created['Name']!r}, expected {name!r}"
    assert created["State"] == "PENDING", (
        f"a fresh connector reported State {created['State']!r}, expected 'PENDING'"
    )
    parts = created["Arn"].split(":")
    assert parts[2] == "lambda" and parts[3] == ctx.region, (
        f"connector ARN {created['Arn']!r} is not a lambda ARN in region {ctx.region!r}"
    )
    assert parts[5] == "network-connector" and parts[6] == connector_id, (
        f"connector ARN {created['Arn']!r} does not end in network-connector:{connector_id}"
    )

    fetched = lc.get_network_connector(Identifier=connector_id)
    assert fetched["Id"] == connector_id, f"Get returned Id {fetched['Id']!r}, expected {connector_id!r}"
    assert fetched["Arn"] == created["Arn"], (
        f"Get Arn {fetched['Arn']!r} disagrees with Create Arn {created['Arn']!r}"
    )
    assert fetched["Name"] == name, f"Get Name {fetched['Name']!r}, expected {name!r}"
    cfg = fetched["Configuration"]["VpcEgressConfiguration"]
    assert cfg["SubnetIds"] == [subnet_id], f"Get SubnetIds {cfg['SubnetIds']!r}, expected {[subnet_id]!r}"
    assert cfg["SecurityGroupIds"] == [sg_id], (
        f"Get SecurityGroupIds {cfg['SecurityGroupIds']!r}, expected {[sg_id]!r}"
    )
    assert cfg["NetworkProtocol"] == "IPv4", f"Get NetworkProtocol {cfg['NetworkProtocol']!r}, expected 'IPv4'"
    assert cfg["AssociatedComputeResourceTypes"] == ["MicroVm"], (
        f"Get AssociatedComputeResourceTypes {cfg['AssociatedComputeResourceTypes']!r}, expected ['MicroVm']"
    )

    # A PENDING connector cannot be deleted (ResourceConflictException). Wait for the terminal
    # ACTIVE state so this check's own cleanup can actually remove what it created, then prove it
    # gone — a free negative on the delete this check already has to perform.
    ready = _wait_active(lc, connector_id, _LEAVES_PENDING_WAIT_S)
    assert ready["Configuration"]["VpcEgressConfiguration"]["SubnetIds"] == [subnet_id], (
        f"ACTIVE connector serves SubnetIds {ready['Configuration']['VpcEgressConfiguration']['SubnetIds']!r}"
    )
    lc.delete_network_connector(Identifier=connector_id)
    deadline = time.monotonic() + _GONE_WAIT_S
    code = message = None
    while time.monotonic() < deadline:
        try:
            lc.get_network_connector(Identifier=connector_id)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            break
        time.sleep(5)
    assert code == "ResourceNotFoundException", (
        f"a deleted connector {connector_id!r} still answered Get (last error {code!r})"
    )
    expected = f"Network connector not found: {created['Arn']}"
    assert message == expected, f"Get of the deleted connector said {message!r}, expected {expected!r}"


def _best_effort_delete(lc, connector_id):
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lc, connector_id, budget_s):
    deadline = time.monotonic() + budget_s
    state = "PENDING"
    while time.monotonic() < deadline:
        got = lc.get_network_connector(Identifier=connector_id)
        state = got["State"]
        if state == "ACTIVE":
            return got
        assert state == "PENDING", (
            f"connector {connector_id!r} reached {state!r} (reason {got.get('StateReason')!r}) "
            "while waiting for ACTIVE"
        )
        time.sleep(2)
    raise AssertionError(f"connector {connector_id!r} stuck in {state!r} after {budget_s}s")


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejections.

    IAM exposes no condition that reports a role has become usable, so the bounded retry on
    the exact propagation messages is what makes the call correct.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            if not any(m in message for m in _TRANSIENT_ROLE_MESSAGES) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _build_network(ctx, ec2, label: str):
    """A throwaway VPC, subnet and security group for this check's own connector; nothing
    ambient is adopted."""
    spec = [{"Key": "sim2real", "Value": label}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    zone = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.91.1.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _operator_role(ctx, iam, name: str) -> str:
    """An operator role Lambda can assume with permissions to manage the connector's ENIs."""
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST_LAMBDA,
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
