"""create-network-connector-idempotent-client-token-returns-same-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-connector-idempotent-client-token-returns-same-resource"
GROUP = "control-plane"
SERVICES = ["lambda-core"]

# Measured on real AWS in us-west-2: a fresh connector stays PENDING for ~250s, and
# DeleteNetworkConnector is refused ResourceConflictException the whole time it is PENDING. Waiting
# it out here, in the body, is what lets the teardown below land inside the engine's own 60s cleanup
# budget instead of it expiring against a connector that Delete cannot yet touch.
_ACTIVE_WAIT_S = 600.0
_ROLE_PROPAGATION_WAIT_S = 120.0
_TEARDOWN_WAIT_S = 300.0
_GONE_WAIT_S = 180.0
_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying CreateNetworkConnector with the same ClientToken and identical params returns the existing connector."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    token = ctx.unique_name("sim2real-token-")
    subnet_id, sg_id = _build_vpc(ctx)
    role_arn = _operator_role(ctx)
    config = _dummy_config(subnet_id, sg_id)

    first = _create_connector(lc, Name=name, Configuration=config, ClientToken=token, OperatorRole=role_arn)
    connector_id = first["Id"]
    ctx.on_cleanup(lambda: _delete_connector(lc, connector_id))

    second = lc.create_network_connector(Name=name, Configuration=config, ClientToken=token, OperatorRole=role_arn)

    assert second["Id"] == first["Id"], "replaying an identical CreateNetworkConnector call must return the same Id"
    assert second["Arn"] == first["Arn"], (
        f"replaying an identical CreateNetworkConnector call returned Arn {second['Arn']!r}, expected {first['Arn']!r}"
    )

    matching = [c for c in _list_connectors(lc) if c["Name"] == name]
    assert len(matching) == 1, f"idempotent replay must not create a duplicate connector, found {len(matching)}"

    _wait_active(lc, connector_id, _ACTIVE_WAIT_S)
    # The connector's ENIs block the VPC teardown, so it is deleted and confirmed gone here.
    _delete_connector(lc, connector_id)


def _dummy_config(subnet_id, sg_id):
    return {
        "VpcEgressConfiguration": {
            "SubnetIds": [subnet_id],
            "SecurityGroupIds": [sg_id],
            "NetworkProtocol": "IPv4",
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejection.

    IAM exposes no pollable condition that reports a role has become usable elsewhere, so the
    bounded retry on the exact propagation messages is what makes the call correct.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = err.get("Message") or ""
            transient = message == _UNASSUMABLE or _NOT_PROPAGATED in message
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _wait_active(lc, ident, budget_s):
    deadline = time.monotonic() + budget_s
    seen = None
    while time.monotonic() < deadline:
        seen = lc.get_network_connector(Identifier=ident)["State"]
        if seen == "ACTIVE":
            return
        assert seen == "PENDING", f"connector {ident!r} reached terminal state {seen!r} while waiting for ACTIVE"
        time.sleep(2)
    raise AssertionError(f"connector {ident!r} stuck in {seen!r} after {budget_s}s")


def _delete_connector(lc, ident) -> None:
    """Teardown that has to retry, because Delete is state-gated: DeleteNetworkConnector is refused
    ResourceConflictException while the connector is PENDING or while an update is InProgress. By
    the time this runs the body has already waited for ACTIVE, so this is defensive, not the
    primary mechanism — but a concurrent update racing in makes it possible, so we retry regardless."""
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
            time.sleep(2)
    gone = time.monotonic() + _GONE_WAIT_S
    while time.monotonic() < gone:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)


def _list_connectors(lc):
    """Every page of ListNetworkConnectors: the account is shared, so page one cannot answer
    a count question."""
    out, marker = [], None
    while True:
        page = lc.list_network_connectors(MaxItems=100, **({"Marker": marker} if marker else {}))
        out.extend(page["NetworkConnectors"])
        marker = page.get("NextMarker")
        if not marker:
            return out


def _build_vpc(ctx):
    """A self-provisioned VPC, subnet and security group; nothing ambient is adopted."""
    ec2 = ctx.client("ec2")
    label = ctx.unique_name("sim2real-lnc-")
    spec = [{"Key": "Name", "Value": label}]

    vpc_id = ec2.create_vpc(CidrBlock="10.95.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

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
        CidrBlock="10.95.1.0/24",
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


OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"


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
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _attached():
            return role_arn
        time.sleep(2)
    raise AssertionError(f"policy {OPERATOR_POLICY_ARN} was not attached to role {name} within 30s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
