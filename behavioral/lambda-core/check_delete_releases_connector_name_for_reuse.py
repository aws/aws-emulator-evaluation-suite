"""delete-releases-connector-name-for-reuse."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-releases-connector-name-for-reuse"
GROUP = "state"
SERVICES = ["lambda-core"]

_ACTIVE_WAIT_S = 600.0
_GONE_WAIT_S = 240.0
_ENI_SETTLE_WAIT_S = 300.0
_ROLE_PROPAGATION_WAIT_S = 180.0
_POLL_S = 2.0

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
# A new role can also fail assumability until IAM propagates. The same message is permanent for
# a wrong trust principal, but this role always trusts lambda.amazonaws.com, so it is retryable.
_NOT_ASSUMABLE = "unable to assume the provided NetworkConnectorOperatorRole"


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A deleted connector frees its Name: re-creating it yields a new Id that Get by name resolves
    to, while the dead Id refuses Update and a second Delete during DELETING succeeds; a second
    Delete that lands after the connector is gone is refused as not found.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    label = ctx.unique_name("sim2real-lnc-reuse-")
    vpc_id, subnet_id, sg_id = _build_vpc(ctx, ec2, label)
    operator = _build_operator_role(ctx, iam, label)
    assert operator.startswith(f"arn:aws:iam::{account}:role/"), (
        f"operator role {operator!r} is not an IAM role in the caller account {account!r}"
    )
    config = _vpc_egress([subnet_id], [sg_id])
    # Tag the connector too, so a leaked one is findable by tag.
    connector_tags = {"sim2real": label}

    first = _create_connector(
        lc, Name=label, Configuration=config, OperatorRole=operator, Tags=connector_tags
    )
    first_id = first["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, first_id))
    first_active = _wait_until(
        ctx,
        lambda: lc.get_network_connector(Identifier=first_id),
        lambda r: r["State"] in ("ACTIVE", "FAILED"),
        _ACTIVE_WAIT_S,
        _POLL_S,
        "the first connector to leave PENDING",
    )
    assert first_active["State"] == "ACTIVE", (
        f"the first connector never became usable: State={first_active['State']!r} "
        f"reason={first_active.get('StateReason')}"
    )
    assert lc.get_network_connector(Identifier=label)["Id"] == first_id, (
        f"Get by name {label!r} does not resolve to the connector that owns it ({first_id!r})"
    )

    # Control: while the original is alive the name is taken; without this, a target that never
    # enforced name uniqueness passes the reuse leg below.
    taken = _error(
        lambda: lc.create_network_connector(
            Name=label, Configuration=config, OperatorRole=operator, Tags=connector_tags
        )
    )
    assert taken == ("ResourceConflictException", f"A network connector with name '{label}' already exists in this account"), (
        f"a duplicate Name while the original is ACTIVE returned {taken!r}, expected "
        "'ResourceConflictException' — the name must be unavailable BEFORE it can be released"
    )
    assert lc.get_network_connector(Identifier=label)["Id"] == first_id, (
        f"the refused duplicate rebound name {label!r} away from {first_id!r}"
    )

    deleted = lc.delete_network_connector(Identifier=first_id)
    assert deleted["State"] == "DELETING", (
        f"Delete reported State {deleted['State']!r}, expected 'DELETING'"
    )
    assert deleted["Id"] == first_id, (
        f"Delete echoed Id {deleted['Id']!r}, expected {first_id!r}"
    )

    # A second delete while DELETING is documented to succeed. Captured now and asserted at
    # the end so it cannot abort the run before the name-release evidence is collected. A target
    # that finishes the delete first answers not found, so a refusal is paired with a Get.
    redelivered = _delete_outcome(lc, first_id)
    gone_at_redelivery = redelivered[0] == "refused" and _get_or_gone(lc, first_id) == "GONE"

    _wait_until(
        ctx,
        lambda: _get_or_gone(lc, first_id),
        lambda v: v == "GONE",
        _GONE_WAIT_S,
        _POLL_S,
        "the first connector to stop answering Get",
    )

    # A mutation on a dead id, which differs from one that never existed.
    dead_update = _error(
        lambda: lc.update_network_connector(Identifier=first_id, Configuration=config)
    )
    assert dead_update == ("ResourceNotFoundException", f"Network connector not found: {first_id}"), (
        f"UpdateNetworkConnector on the deleted id {first_id!r} returned {dead_update!r}, "
        "expected ('ResourceNotFoundException', 'Network connector not found: ...')"
    )
    enumerated = {c["Id"] for c in _list_connectors(lc)}
    assert first_id not in enumerated, (
        f"the deleted connector {first_id!r} is still enumerated by ListNetworkConnectors "
        f"({len(enumerated)} connectors in the account)"
    )

    # Name uniqueness is enforced synchronously (the control above), so acceptance here is the
    # release.
    second = _create_connector(
        lc, Name=label, Configuration=config, OperatorRole=operator, Tags=connector_tags
    )
    second_id = second["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, second_id))
    assert second["Name"] == label, (
        f"the reusing create echoed Name {second['Name']!r}, expected {label!r}"
    )
    assert second_id != first_id, (
        f"re-creating with the freed name {label!r} returned the DEAD id {first_id!r}; a "
        "released name must produce a brand-new connector, not resurrect the old one"
    )
    assert second["State"] == "PENDING", (
        f"the reusing create reported State {second['State']!r}, expected 'PENDING'"
    )
    rebound = lc.get_network_connector(Identifier=label)
    assert rebound["Id"] == second_id, (
        f"Get by name {label!r} resolves to {rebound['Id']!r}, expected the new connector "
        f"{second_id!r} — the name index must be rebound, not left pointing at a tombstone"
    )
    assert rebound["Arn"] == second["Arn"], (
        f"Get by name serves Arn {rebound['Arn']!r}, expected {second['Arn']!r}"
    )

    if gone_at_redelivery:
        assert redelivered[1] == "ResourceNotFoundException", (
            f"a second DeleteNetworkConnector after the connector was gone returned "
            f"{redelivered[1]!r}, expected 'ResourceNotFoundException'"
        )
    else:
        assert redelivered[0] == "accepted", (
            f"a second DeleteNetworkConnector while the connector was DELETING returned "
            f"{redelivered[1]!r}; DeleteNetworkConnector is documented idempotent, so it must "
            "succeed without error"
        )
        assert redelivered[1]["Id"] == first_id, (
            f"the idempotent second delete echoed Id {redelivered[1]['Id']!r}, expected {first_id!r}"
        )
        assert redelivered[1]["State"] == "DELETING", (
            f"the idempotent second delete reported State {redelivered[1]['State']!r}, expected "
            "'DELETING'"
        )

    # A PENDING connector cannot be deleted, and its ENIs block VPC teardown, so the second
    # connector is driven to ACTIVE and deleted here rather than in cleanup.
    second_active = _wait_until(
        ctx,
        lambda: lc.get_network_connector(Identifier=second_id),
        lambda r: r["State"] in ("ACTIVE", "FAILED"),
        _ACTIVE_WAIT_S,
        _POLL_S,
        "the reusing connector to leave PENDING",
    )
    assert second_active["State"] == "ACTIVE", (
        f"the connector created on the reused name never became usable: "
        f"State={second_active['State']!r} reason={second_active.get('StateReason')}"
    )
    lc.delete_network_connector(Identifier=second_id)
    _wait_until(
        ctx,
        lambda: _get_or_gone(lc, second_id),
        lambda v: v == "GONE",
        _GONE_WAIT_S,
        _POLL_S,
        "the reusing connector to stop answering Get",
    )
    # ENI release follows the connectors' deletion; raises if ENIs are still in the VPC at the
    # deadline, since the subnets and VPC cannot be torn down while they exist.
    _wait_until(
        ctx,
        lambda: _eni_topology(ec2, vpc_id),
        lambda t: t == {},
        _ENI_SETTLE_WAIT_S,
        _POLL_S,
        "deleting both connectors to release every ENI in the VPC",
    )


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


def _delete_outcome(lc, ident):
    """('accepted', response) or ('refused', error code); the caller asserts the outcome."""
    try:
        return ("accepted", lc.delete_network_connector(Identifier=ident))
    except ClientError as exc:
        return ("refused", exc.response.get("Error", {}).get("Code"))


def _wait_until(ctx, probe, predicate, deadline_s, interval_s, what):
    """Bounded retry, capped by the run's remaining time. RAISES on timeout."""
    left = ctx.time_left()
    bound = deadline_s if left is None else min(deadline_s, left)
    deadline = time.monotonic() + bound
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"waited {bound:.0f}s for {what} and it never happened (last={last!r})")


def _get_or_gone(lc, ident):
    try:
        return lc.get_network_connector(Identifier=ident)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise


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
    check's own, so every ENI in it belongs to its connectors."""
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


def _build_vpc(ctx, ec2, label):
    """A dedicated VPC with one subnet and one security group, so every ENI in it is
    attributable to this check's connectors."""
    spec = [{"Key": "sim2real", "Value": label}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert zones, "region reports no available availability zones"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.93.1.0/24",
        AvailabilityZone=zones[0],
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
    return vpc_id, subnet_id, sg_id


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
            propagating = _NOT_PROPAGATED in message or _NOT_ASSUMABLE in message
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _best_effort_delete(lc, ident):
    """Safety net: the body already deletes both connectors and proves them gone."""
    try:
        lc.delete_network_connector(Identifier=ident)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
