"""list-network-connectors-state-filter-scoping."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-network-connectors-state-filter-scoping"
GROUP = "control-plane"
SERVICES = ["lambda-core"]

# Measured on real AWS in us-west-2: CreateNetworkConnector validates a freshly-attached
# OperatorRole in two synchronous stages — the trust policy (assume) and then the EC2 permissions —
# and while IAM is still propagating either one, the call rejects a role that is (or will be)
# perfectly usable. The bounded retry on those two exact transient messages is the correctness
# mechanism; the sleep between attempts only makes it cheaper.
_ROLE_PROPAGATION_WAIT_S = 120.0
_TRANSIENT_ROLE_MESSAGES = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role.",
    "Encountered unauthorized operation while calling EC2 due to invalid "
    "ConnectorOperatorRole permissions",
)

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"
_ACTIVE_WAIT_S = 600.0
_TEARDOWN_WAIT_S = 600.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNetworkConnectors State= filter includes a matching connector and excludes it under a
    non-matching filter, and re-partitions it once the connector reaches ACTIVE."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    subnet_id, sg_id = _network(ctx)
    role_arn = _operator_role(ctx, name)
    created = _create_connector(
        lc, Name=name, Configuration=_dummy_config(subnet_id, sg_id), OperatorRole=role_arn
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_and_wait_gone(lc, connector_id))
    assert created["State"] == "PENDING", f"expected PENDING on create, got {created['State']!r}"

    # PENDING only moves forward to ACTIVE, so a Get that still reports PENDING after a listing
    # proves the connector was PENDING for the whole listing; only then is that listing graded.
    pending_ids = {c["Id"] for c in _list_connectors(lc, State="PENDING")}
    if _state(lc, connector_id) == "PENDING":
        assert connector_id in pending_ids, (
            "freshly created PENDING connector missing from State=PENDING filter"
        )
    active_ids = {c["Id"] for c in _list_connectors(lc, State="ACTIVE")}
    if _state(lc, connector_id) == "PENDING":
        assert connector_id not in active_ids, (
            "a PENDING connector must not appear under State=ACTIVE filter"
        )

    _wait_active(lc, connector_id, _budget_s(ctx, _ACTIVE_WAIT_S), ctx=ctx)
    active_ids = {c["Id"] for c in _list_connectors(lc, State="ACTIVE")}
    assert connector_id in active_ids, "an ACTIVE connector is missing from the State=ACTIVE filter"
    pending_ids = {c["Id"] for c in _list_connectors(lc, State="PENDING")}
    assert connector_id not in pending_ids, "an ACTIVE connector still appears under State=PENDING"

    # The connector's ENIs block the VPC teardown, so it is deleted and confirmed gone here.
    _delete_and_wait_gone(lc, connector_id)


def _dummy_config(subnet_id, sg_id):
    return {
        "VpcEgressConfiguration": {
            "SubnetIds": [subnet_id],
            "SecurityGroupIds": [sg_id],
            "NetworkProtocol": "IPv4",
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _state(lc, ident):
    return lc.get_network_connector(Identifier=ident)["State"]


def _list_connectors(lc, **kwargs):
    """Every page of ListNetworkConnectors: the account is shared, so page one cannot answer a
    membership question."""
    out, marker = [], None
    while True:
        page = lc.list_network_connectors(MaxItems=100, **kwargs, **({"Marker": marker} if marker else {}))
        out.extend(page["NetworkConnectors"])
        marker = page.get("NextMarker")
        if not marker:
            return out


def _wait_active(lc, ident, budget_s, ctx=None):
    deadline = time.monotonic() + budget_s
    seen = None
    while True:
        got = lc.get_network_connector(Identifier=ident)
        seen = got["State"]
        if seen == "ACTIVE":
            return got
        assert seen == "PENDING", (
            f"connector {ident!r} reached {seen!r} (reason {got.get('StateReason')!r}) while waiting for ACTIVE"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"connector {ident!r} to become ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"connector {ident!r} stuck in {seen!r} after {budget_s:.0f}s")


def _delete_and_wait_gone(lc, ident):
    """Delete, retrying the state-gated ResourceConflictException, then poll Get until 404."""
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
    while time.monotonic() < deadline:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"connector {ident!r} still answers Get after {_TEARDOWN_WAIT_S}s")


def _network(ctx):
    """A throwaway VPC, subnet and security group created (and torn down) by this check; nothing
    ambient is adopted."""
    ec2 = ctx.client("ec2")
    label = ctx.unique_name("sim2real-lnc-net-")
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
        )[
            "AvailabilityZones"
        ]
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


def _operator_role(ctx, name):
    """An IAM role with AWSLambdaNetworkConnectorOperatorPolicy attached, usable as OperatorRole."""
    iam = ctx.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust_policy, Tags=[{"Key": "sim2real", "Value": name}]
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))
    return role_arn


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejection.

    IAM exposes no condition that reports a role has become usable, so this is the one
    sanctioned sleep: the bounded retry on the exact propagation message is what makes the
    call correct, the sleep only makes it cheaper.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            if message not in _TRANSIENT_ROLE_MESSAGES or time.monotonic() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
