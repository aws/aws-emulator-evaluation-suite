"""update-shrinking-config-deprovisions-dropped-subnet-eni."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-shrinking-config-deprovisions-dropped-subnet-eni"
GROUP = "state"
SERVICES = ["lambda-core"]

# create -> ACTIVE takes ~250s and update -> LastUpdateStatus Successful ~257s.
_ACTIVE_WAIT_S = 600.0
_UPDATE_WAIT_S = 600.0
_GONE_WAIT_S = 240.0
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
# A new, correctly-trusted role also reports this assume failure while its trust policy is
# still propagating.
_NOT_ASSUMABLE_YET = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A strict-subset UpdateNetworkConnector replaces rather than merges: Get serves only the kept
    subnet and security group and LastModified advances, while no connector ENI is ever visible
    to the caller.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    label = ctx.unique_name("sim2real-lnc-shrink-")
    vpc_id, subnets = _default_network(ec2, want=2, ctx=ctx)
    kept_subnet, dropped_subnet = subnets[0], subnets[1]
    kept_sg, dropped_sg = _build_security_groups(ctx, ec2, vpc_id, label)
    operator = _build_operator_role(ctx, iam, label)
    assert operator.startswith(f"arn:aws:iam::{account}:role/"), (
        f"operator role {operator!r} is not an IAM role in the caller account {account!r}"
    )

    # These security groups are new and unattached, so any later ENI carrying one is this
    # connector's, whatever else lives in the shared VPC.
    before = _eni_topology_by_sg(ec2, [kept_sg, dropped_sg])
    assert before == {}, f"a freshly created security group already carries an ENI: {before!r}"

    created = _create_connector(
        lc,
        Name=label,
        Configuration=_vpc_egress(
            [kept_subnet, dropped_subnet], [kept_sg, dropped_sg]
        ),
        OperatorRole=operator,
        Tags={"sim2real": label},
    )
    ident = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, ident))
    assert created["State"] == "PENDING", (
        f"a fresh connector reported State {created['State']!r}, expected 'PENDING'"
    )

    active = _wait_until(
        ctx,
        lambda: lc.get_network_connector(Identifier=ident),
        lambda r: r["State"] in ("ACTIVE", "FAILED"),
        _ACTIVE_WAIT_S,
        _POLL_S,
        "connector to leave PENDING",
    )
    assert active["State"] == "ACTIVE", (
        f"connector settled as {active['State']!r}, expected 'ACTIVE' "
        f"(reason={active.get('StateReason')})"
    )
    modified_before = active["LastModified"]

    # This connector type exposes no ENI to the caller's DescribeNetworkInterfaces. Read once the
    # connector is ACTIVE, when a connector that did expose them would already show its ENIs.
    wide = _eni_topology_by_sg(ec2, [kept_sg, dropped_sg])
    assert wide == {}, (
        f"connector ENIs sit in subnets {sorted(wide)!r} — this connector type never exposes "
        "an ENI to the caller's DescribeNetworkInterfaces, so this must stay empty"
    )

    # Shrink, not grow: a target that merges the submitted configuration into the stored one
    # would still serve both elements, which a growing update cannot reveal.
    accepted = lc.update_network_connector(
        Identifier=ident,
        Configuration=_vpc_egress([kept_subnet], [kept_sg]),
    )
    assert accepted["LastUpdateStatus"] == "InProgress", (
        f"an accepted update reported LastUpdateStatus {accepted.get('LastUpdateStatus')!r}, "
        "expected 'InProgress'"
    )

    settled_status = _wait_until(
        ctx,
        lambda: lc.get_network_connector(Identifier=ident),
        lambda r: r["LastUpdateStatus"] != "InProgress",
        _UPDATE_WAIT_S,
        _POLL_S,
        "update to leave InProgress",
    )
    assert settled_status["LastUpdateStatus"] == "Successful", (
        f"the shrinking update settled as {settled_status['LastUpdateStatus']!r}, expected "
        f"'Successful' (code={settled_status.get('LastUpdateStatusReasonCode')} "
        f"reason={settled_status.get('LastUpdateStatusReason')})"
    )

    settled = lc.get_network_connector(Identifier=ident)
    egress = settled["Configuration"]["VpcEgressConfiguration"]
    assert egress["SubnetIds"] == [kept_subnet], (
        f"after a strict-subset update Get serves SubnetIds {egress['SubnetIds']!r}, expected "
        f"exactly [{kept_subnet!r}] — Update REPLACES the configuration, it does not merge, so "
        f"{dropped_subnet!r} must be gone"
    )
    assert egress["SecurityGroupIds"] == [kept_sg], (
        f"after a strict-subset update Get serves SecurityGroupIds "
        f"{egress['SecurityGroupIds']!r}, expected exactly [{kept_sg!r}]; {dropped_sg!r} must be gone"
    )
    assert settled["State"] == "ACTIVE", (
        f"State is {settled['State']!r} after a Successful update, expected 'ACTIVE' — an "
        "update never takes the connector out of service"
    )
    assert settled["LastModified"] > modified_before, (
        f"LastModified did not advance across a successful update: {modified_before!r} -> "
        f"{settled['LastModified']!r}"
    )

    # Read once the update reports Successful, when the kept subnet's ENI would be in place.
    narrow = _eni_topology_by_sg(ec2, [kept_sg, dropped_sg])
    assert narrow == {}, (
        f"connector ENIs sit in subnets {sorted(narrow)!r} after the update — this connector "
        "type never exposes an ENI to the caller, before or after a shrinking update"
    )

    _delete_and_prove_gone(ctx, lc, ident, label)
    left = _eni_topology_by_sg(ec2, [kept_sg, dropped_sg])
    assert left == {}, (
        f"an ENI is visible after the connector was deleted: {left!r} — the confirmed "
        "invariant is that none is ever provisioned, so none can survive deletion either"
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


def _error_code(fn):
    """The (Error.Code, Error.Message) fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


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


def _eni_topology_by_sg(ec2, sg_ids):
    """subnet id -> {ENI ids, security group ids} for every ENI carrying any of *sg_ids*;
    filtering by this check's own groups attributes ENIs regardless of what else is in the VPC."""
    topology = {}
    pages = ec2.get_paginator("describe_network_interfaces").paginate(
        Filters=[{"Name": "group-id", "Values": list(sg_ids)}]
    )
    for page in pages:
        for eni in page["NetworkInterfaces"]:
            entry = topology.setdefault(
                eni["SubnetId"], {"ids": frozenset(), "groups": frozenset()}
            )
            entry["ids"] = entry["ids"] | {eni["NetworkInterfaceId"]}
            entry["groups"] = entry["groups"] | {g["GroupId"] for g in eni["Groups"]}
    return topology


def _default_network(ec2, want=2, *, ctx):
    """The shared network's VPC and one subnet per AZ for *want* AZs; creates nothing, so a
    full per-region VPC quota cannot block the check."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "account has no shared network VPC to adopt"
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_zone = {}
    for s in subnets:
        by_zone.setdefault(s["AvailabilityZone"], s["SubnetId"])
    zones = sorted(by_zone)
    assert len(zones) >= want, f"shared network offers only zones {zones!r}, need {want}"
    return vpc_id, [by_zone[z] for z in zones[:want]]


def _build_security_groups(ctx, ec2, vpc_id, label):
    """Two new security groups in the shared VPC; their uniqueness makes ENI attribution sound."""
    spec = [{"Key": "sim2real", "Value": label}]
    groups = []
    for suffix in ("a", "b"):
        gid = ec2.create_security_group(
            GroupName=f"{label}-{suffix}",
            Description="sim2real lambda-core network connector egress",
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
        )["GroupId"]
        ctx.on_cleanup(lambda g=gid: _delete_security_group_when_free(ec2, g))
        groups.append(gid)
    return groups[0], groups[1]


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
    """CreateNetworkConnector, retrying only the two IAM-propagation rejections; IAM exposes no
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


def _delete_and_prove_gone(ctx, lc, ident, name):
    deleted = lc.delete_network_connector(Identifier=ident)
    assert deleted["State"] == "DELETING", (
        f"Delete reported State {deleted['State']!r}, expected 'DELETING'"
    )
    _wait_until(
        ctx,
        lambda: _get_or_gone(lc, ident),
        lambda v: v == "GONE",
        _GONE_WAIT_S,
        _POLL_S,
        "the deleted connector to stop answering Get",
    )
    got = _error_code(lambda: lc.get_network_connector(Identifier=name))
    assert got == ("ResourceNotFoundException", f"Network connector not found: {name}"), (
        f"the deleted connector is still resolvable by name {name!r}, got {got!r}"
    )


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



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
