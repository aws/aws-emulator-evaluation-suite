"""create-network-connector-token-reuse-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-connector-token-reuse-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda-core"]

# Measured on real AWS elsewhere in this suite: a PENDING connector refuses Delete with
# ResourceConflictException, and IAM role/policy propagation exposes no pollable condition, only a
# transient rejection message to retry against.
_ACTIVE_WAIT_S = 600.0
_GONE_WAIT_S = 180.0
_TEARDOWN_WAIT_S = 900.0
_ROLE_PROPAGATION_WAIT_S = 120.0
_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientToken with the same Name but different Configuration is rejected; original is untouched."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-lnc-tk-")
    subnet_id, other_subnet_id, sg_id = _build_vpc(ctx, ec2, label)
    role_arn = _operator_role(ctx, iam, label)
    token = ctx.unique_name("sim2real-token-")
    original_config = _dummy_config([subnet_id], sg_id)

    first = _create_connector(
        lc,
        Name=label,
        Configuration=original_config,
        ClientToken=token,
        OperatorRole=role_arn,
        Tags={"sim2real": label},
    )
    connector_id = first["Id"]
    ctx.on_cleanup(lambda: _delete_connector(lc, connector_id))

    code, message = _error(
        lambda: lc.create_network_connector(
            Name=label,
            Configuration=_dummy_config([other_subnet_id], sg_id),
            ClientToken=token,
            OperatorRole=role_arn,
        )
    )
    assert code == "ResourceConflictException", (
        f"expected ResourceConflictException for a mismatched-Configuration token replay, got {code}"
    )
    assert message == "A request with the same client token but different parameters was already submitted", (
        f"mismatched-token refusal message: got {message!r}"
    )

    # effect absent: the original connector's configuration must be unchanged by the rejected attempt
    unchanged = lc.get_network_connector(Identifier=connector_id)
    assert unchanged["Configuration"]["VpcEgressConfiguration"]["SubnetIds"] == [subnet_id], (
        f"the rejected mismatch attempt altered the original connector's subnets: "
        f"{unchanged['Configuration']['VpcEgressConfiguration']['SubnetIds']!r}"
    )

    listing = lc.list_network_connectors(MaxItems=100)
    matching = [c for c in listing["NetworkConnectors"] if c["Name"] == label]
    assert len(matching) == 1, (
        f"a rejected token-reuse-mismatch create must not have persisted a second connector: {matching}"
    )

    # positive control: replaying the SAME token with IDENTICAL params still succeeds idempotently
    replay = lc.create_network_connector(
        Name=label,
        Configuration=original_config,
        ClientToken=token,
        OperatorRole=role_arn,
        Tags={"sim2real": label},
    )
    assert replay["Id"] == connector_id, (
        f"replaying the identical token/params minted {replay['Id']!r} instead of {connector_id!r}"
    )
    assert replay["Arn"] == first["Arn"], f"replay returned Arn {replay['Arn']!r}, expected {first['Arn']!r}"

    # clear PENDING before returning so cleanup's delete is not refused by the state gate
    _poll_until(
        lambda: lc.get_network_connector(Identifier=connector_id),
        lambda resp: resp["State"] in ("ACTIVE", "FAILED"),
        timeout_s=_ACTIVE_WAIT_S,
        interval_s=15,
    )


def _dummy_config(subnet_ids, sg_id):
    return {
        "VpcEgressConfiguration": {
            "SubnetIds": subnet_ids,
            "SecurityGroupIds": [sg_id],
            "NetworkProtocol": "IPv4",
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises; a SUCCESS raises instead of returning a
    falsy sentinel that would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("the mismatched-token create unexpectedly SUCCEEDED; real AWS rejects it")


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_connector(lc, **kwargs):
    """IAM propagation exposes no pollable condition; the bounded retry on the exact message is
    what makes this correct."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            # A fresh role answers either message until IAM propagation completes.
            transient = message == _UNASSUMABLE or _NOT_PROPAGATED in message
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_connector(lc, ident) -> None:
    """Delete is refused ResourceConflictException while the connector is state-gated; retry the
    delete itself until it is accepted, then confirm the read reflects it."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            lc.delete_network_connector(Identifier=ident)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(10)
    gone = time.monotonic() + _GONE_WAIT_S
    while time.monotonic() < gone:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)


def _usable_zones(ec2):
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
    assert zones, "region offers no available zones"
    return zones


def _build_vpc(ctx, ec2, label: str):
    """A VPC of our own, tagged, with two distinct subnets — never the ambient default VPC, which a
    freshly provisioned account may not have."""
    spec = [{"Key": "sim2real", "Value": label}]
    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    zones = _usable_zones(ec2)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.97.1.0/24",
        AvailabilityZone=zones[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    other_zone = zones[1] if len(zones) > 1 else zones[0]
    other_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.97.2.0/24",
        AvailabilityZone=other_zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=other_subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, other_subnet_id, sg_id


def _operator_role(ctx, iam, label: str):
    """Create an IAM role with AWSLambdaNetworkConnectorOperatorPolicy attached, usable as OperatorRole."""
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
        Tags=[{"Key": "sim2real", "Value": label}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not _attached():
        time.sleep(2)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
