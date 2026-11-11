"""failed-update-keeps-connector-active-on-previous-config."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failed-update-keeps-connector-active-on-previous-config"
GROUP = "state"
SERVICES = ["lambda-core"]

_ACTIVE_WAIT_S = 600.0
_UPDATE_WAIT_S = 600.0
_GONE_WAIT_S = 240.0
_ROLE_PROPAGATION_WAIT_S = 180.0

_TRUST_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
# A new, correctly-trusted role also reports this assume failure while its trust policy is
# still propagating.
_NOT_ASSUMABLE_YET = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
_INVALID_SUBNET_CODE = "InvalidSubnetID.NotFound"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An update naming a non-existent subnet is rejected synchronously with
    InvalidParameterValueException; the connector stays ACTIVE on its previous config with no
    LastUpdateStatus, and a later valid update still settles Successful.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    label = ctx.unique_name("sim2real-lnc-badupd-")
    vpc_id, subnet_id, second_subnet_id, sg_id = _build_vpc(ctx, ec2, label)
    operator = _build_operator_role(ctx, iam, label)
    assert operator.startswith(f"arn:aws:iam::{account}:role/"), (
        f"operator role {operator!r} is not an IAM role in the caller account {account!r}"
    )

    created = _create_connector(
        lc,
        Name=label,
        Configuration=_vpc_egress([subnet_id], [sg_id]),
        OperatorRole=operator,
        Tags={"sim2real": label},
    )
    ident = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, ident))
    active = _wait_until(
        lambda: lc.get_network_connector(Identifier=ident),
        lambda r: r["State"] in ("ACTIVE", "FAILED"),
        _ACTIVE_WAIT_S,
        15.0,
        "connector to leave PENDING",
    )
    assert active["State"] == "ACTIVE", (
        f"the positive control never became usable: State={active['State']!r} "
        f"reason={active.get('StateReason')}"
    )
    assert "LastUpdateStatus" not in active, (
        f"a connector with no update ever issued already reports LastUpdateStatus "
        f"{active.get('LastUpdateStatus')!r} — expected the field to be absent until the "
        "first update is accepted"
    )
    # This connector type's ENIs are never visible to the caller's DescribeNetworkInterfaces,
    # even once ACTIVE; the VPC is this check's own, so any ENI here is the connector's.
    baseline_topology = _eni_topology(ec2, vpc_id)
    assert baseline_topology == {}, (
        f"an ACTIVE connector's VPC carries ENIs visible to the caller: {baseline_topology!r} — "
        "real AWS provisions this connector type's ENIs outside the caller's own view"
    )

    # Well-formed against ^subnet-[0-9a-z]*$ and guaranteed not to exist.
    bogus_subnet = "subnet-" + uuid.uuid4().hex[:17]
    code, message = _error(
        lambda: lc.update_network_connector(
            Identifier=ident,
            Configuration=_vpc_egress([bogus_subnet], [sg_id]),
        )
    )
    # Subnet existence is validated synchronously against EC2, not via LastUpdateStatus.
    assert code == "InvalidParameterValueException", (
        f"an update naming a non-existent subnet raised {code!r}, expected "
        "'InvalidParameterValueException'"
    )
    assert message == (
        f"Error occurred while DescribeSubnets. EC2 Error Code: {_INVALID_SUBNET_CODE}. "
        f"EC2 Error Message: The subnet ID '{bogus_subnet}' does not exist"
    ), (
        f"expected the {_INVALID_SUBNET_CODE!r} EC2 validation failure naming {bogus_subnet!r}, "
        f"got message={message!r}"
    )

    failed = lc.get_network_connector(Identifier=ident)
    assert failed["State"] == "ACTIVE", (
        f"State is {failed['State']!r} after a rejected update, expected 'ACTIVE' — a "
        "synchronously rejected update must not take a working connector out of service"
    )
    egress = failed["Configuration"]["VpcEgressConfiguration"]
    assert egress["SubnetIds"] == [subnet_id], (
        f"after a rejected update Get serves SubnetIds {egress['SubnetIds']!r}, expected the "
        f"PREVIOUS set [{subnet_id!r}] — the rejected {bogus_subnet!r} must never be persisted"
    )
    assert "LastUpdateStatus" not in failed, (
        f"a synchronously rejected update populated LastUpdateStatus "
        f"{failed.get('LastUpdateStatus')!r} — the request never reached the async update "
        "machinery, so no update record should exist"
    )
    listed_active = {c["Id"] for c in _list_connectors(lc, State="ACTIVE")}
    assert ident in listed_active, (
        f"connector {ident!r} vanished from List State=ACTIVE after a rejected update"
    )
    listed_failed = {c["Id"] for c in _list_connectors(lc, State="FAILED")}
    assert ident not in listed_failed, (
        f"connector {ident!r} is enumerated under List State=FAILED after a rejected UPDATE"
    )
    still_topology = _eni_topology(ec2, vpc_id)
    assert still_topology == {}, (
        f"a rejected update left ENIs visible to the caller: {still_topology!r}, expected none"
    )

    # A valid update must still settle, or a target rejecting every update would pass above.
    accepted = lc.update_network_connector(
        Identifier=ident,
        Configuration=_vpc_egress([second_subnet_id], [sg_id]),
    )
    assert accepted["LastUpdateStatus"] == "InProgress", (
        f"a valid update reported LastUpdateStatus {accepted.get('LastUpdateStatus')!r}, "
        "expected 'InProgress' — the earlier rejection must not have wedged the connector"
    )
    settled = _wait_until(
        lambda: lc.get_network_connector(Identifier=ident),
        lambda r: r["LastUpdateStatus"] != "InProgress",
        _UPDATE_WAIT_S,
        10.0,
        "the valid update to leave InProgress",
    )
    assert settled["LastUpdateStatus"] == "Successful", (
        f"the valid update settled as {settled['LastUpdateStatus']!r}, expected 'Successful' "
        f"(code={settled.get('LastUpdateStatusReasonCode')}) — the earlier rejection must be "
        "specific to the bad subnet, not a connector that is now wedged"
    )
    settled_egress = settled["Configuration"]["VpcEgressConfiguration"]
    assert settled_egress["SubnetIds"] == [second_subnet_id], (
        f"after the valid update Get serves SubnetIds {settled_egress['SubnetIds']!r}, "
        f"expected [{second_subnet_id!r}]"
    )

    _delete_and_prove_gone(lc, ident, label)


def _vpc_egress(subnet_ids, sg_ids, protocol="IPv4"):
    return {
        "VpcEgressConfiguration": {
            "SubnetIds": list(subnet_ids),
            "SecurityGroupIds": list(sg_ids),
            "NetworkProtocol": protocol,
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _wait_until(probe, predicate, deadline_s, interval_s, what):
    """Bounded retry. RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"waited {deadline_s}s for {what} and it never happened (last={last!r})")


def _list_connectors(lc, **kwargs):
    """Every page of ListNetworkConnectors, so a claim about membership is not a claim about
    page one."""
    out = []
    marker = None
    while True:
        params = dict(kwargs)
        if marker:
            params["Marker"] = marker
        page = lc.list_network_connectors(**params)
        out.extend(page["NetworkConnectors"])
        marker = page.get("NextMarker")
        if not marker:
            return out


def _eni_topology(ec2, vpc_id):
    """subnet id -> {ENI ids, security group ids} for every ENI in *vpc_id*; the VPC is this
    check's own, so every ENI in it belongs to the connector."""
    topology = {}
    pages = ec2.get_paginator("describe_network_interfaces").paginate(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    for page in pages:
        for eni in page["NetworkInterfaces"]:
            entry = topology.setdefault(
                eni["SubnetId"], {"ids": frozenset(), "groups": frozenset()}
            )
            entry["ids"] = entry["ids"] | {eni["NetworkInterfaceId"]}
            entry["groups"] = entry["groups"] | {g["GroupId"] for g in eni["Groups"]}
    return topology


def _usable_zones(ec2, want):
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(zones) >= want, f"region offers only {zones!r}, need {want} available zones"
    return zones[:want]


def _build_vpc(ctx, ec2, label):
    """A dedicated VPC with two subnets in distinct AZs and one security group; the second
    subnet is the target of the valid update."""
    spec = [{"Key": "sim2real", "Value": label}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    zones = _usable_zones(ec2, 2)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.92.1.0/24",
        AvailabilityZone=zones[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    second_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.92.2.0/24",
        AvailabilityZone=zones[1],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=second_subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return vpc_id, subnet_id, second_subnet_id, sg_id


def _build_operator_role(ctx, iam, name):
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_LAMBDA),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY))
    return arn


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejections; IAM exposes no
    condition reporting that a role has become usable."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            still_propagating = _NOT_PROPAGATED in message or _NOT_ASSUMABLE_YET in message
            if not still_propagating or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _delete_and_prove_gone(lc, ident, name):
    deleted = lc.delete_network_connector(Identifier=ident)
    assert deleted["State"] == "DELETING", (
        f"Delete reported State {deleted['State']!r}, expected 'DELETING'"
    )
    _wait_until(
        lambda: _get_or_gone(lc, ident),
        lambda v: v == "GONE",
        _GONE_WAIT_S,
        10.0,
        "the deleted connector to stop answering Get",
    )
    code, message = _error(lambda: lc.get_network_connector(Identifier=name))
    assert code == "ResourceNotFoundException", (
        f"the deleted connector is still resolvable by name {name!r}: {code!r}"
    )
    assert message == f"Network connector not found: {name}", message


def _get_or_gone(lc, ident):
    try:
        return lc.get_network_connector(Identifier=ident)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise


def _best_effort_delete(lc, ident):
    """Safety net: the body already deletes the connector and proves it gone."""
    try:
        lc.delete_network_connector(Identifier=ident)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
