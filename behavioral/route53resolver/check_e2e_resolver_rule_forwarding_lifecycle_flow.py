"""e2e-resolver-rule-forwarding-lifecycle-flow."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-resolver-rule-forwarding-lifecycle-flow"
GROUP = "state-machine"
SERVICES = ["route53resolver"]

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-r53r"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """An outbound endpoint, a FORWARD rule targeting it and a VPC association reach their
    terminal states; after teardown the association, rule and endpoint are absent from reads."""
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids, sg_id, owns_network = _provision_network(ctx, subnet_count=2)

    endpoint = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-ep-"),
        Direction="OUTBOUND",
        SecurityGroupIds=[sg_id],
        IpAddresses=[{"SubnetId": s} for s in subnet_ids],
        Tags=TAGS_KV,
    )["ResolverEndpoint"]
    endpoint_id = endpoint["Id"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(ctx, endpoint_id))

    endpoint = _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"],
        lambda e: e["Status"] in ("OPERATIONAL", "ACTION_NEEDED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert endpoint["Status"] == "OPERATIONAL", f"endpoint reached {endpoint['Status']}"

    domain_name = f"{ctx.unique_name('sim2real-')}.test"
    rule = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-rule-"),
        RuleType="FORWARD",
        DomainName=domain_name,
        TargetIps=[{"Ip": "10.0.0.53", "Port": 53}],
        ResolverEndpointId=endpoint_id,
        Tags=TAGS_KV,
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule(ctx, rule_id))

    assoc = r53r.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id, Name=ctx.unique_name("sim2real-r53r-assoc-")
    )["ResolverRuleAssociation"]
    assoc_id = assoc["Id"]

    final_assoc = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final_assoc["Status"] == "COMPLETE", f"association reached {final_assoc['Status']}"
    assert final_assoc["ResolverRuleId"] == rule_id, (
        f"association's ResolverRuleId {final_assoc['ResolverRuleId']!r} != {rule_id!r}"
    )

    r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    _poll_until(
        lambda: _get_rule_assoc_or_none(ctx, assoc_id),
        lambda v: v is None,
        timeout_s=90.0,
        interval_s=3.0,
    )

    r53r.delete_resolver_rule(ResolverRuleId=rule_id)
    _poll_until(
        lambda: _get_rule_or_none(ctx, rule_id),
        lambda v: v is None,
        timeout_s=60.0,
        interval_s=3.0,
    )

    r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id)
    _poll_until(
        lambda: _get_endpoint_or_none(ctx, endpoint_id),
        lambda v: v is None,
        timeout_s=300.0,
        interval_s=10.0,
    )

    assert _get_rule_assoc_or_none(ctx, assoc_id) is None, "association still visible after disassociate+delete"
    assert _get_rule_or_none(ctx, rule_id) is None, f"rule {rule_id} still visible after delete"
    assert _get_endpoint_or_none(ctx, endpoint_id) is None, f"endpoint {endpoint_id} still visible after delete"

    # The endpoint's ENIs are released asynchronously after DeleteResolverEndpoint's read
    # reports it gone, so the network is torn down here with retries rather than in on_cleanup.
    _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id), timeout_s=180.0)
    assert _get_sg_or_none(ctx, sg_id) is None, f"security group {sg_id} still visible after delete"

    if owns_network:
        for subnet_id in subnet_ids:
            _retry_delete(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s), timeout_s=180.0)
            assert _get_subnet_or_none(ctx, subnet_id) is None, (
                f"subnet {subnet_id} still visible after delete"
            )
        _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id), timeout_s=180.0)
        assert _get_vpc_or_none(ctx, vpc_id) is None, f"VPC {vpc_id} still visible after delete"


# ===== helpers =====


def _provision_network(ctx: Any, subnet_count: int = 2) -> tuple[str, list[str], str, bool]:
    """Return (vpc_id, subnet_ids, sg_id, owns_network), creating a dedicated VPC and subnets.

    If VPC creation is refused (e.g. at quota) an existing network is borrowed and owns_network is
    False, so the caller must not delete it. The security group is always created fresh.
    """
    ec2 = ctx.client("ec2")
    vpc_id = None
    owns_network = False
    try:
        vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
        owns_network = True
        ctx.on_cleanup(lambda v=vpc_id: _safe_delete_vpc(ctx, v))
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=TAGS_KV + [{"Key": "Name", "Value": ctx.unique_name("sim2real-r53r-vpc-")}],
        )
    except ClientError:
        vpc_id = None
        owns_network = False

    subnet_ids: list[str] = []
    if owns_network:
        azs = [
            a["ZoneName"]
            for a in ec2.describe_availability_zones(
                Filters=[
                    {"Name": "state", "Values": ["available"]},
                    {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
                ]
            )["AvailabilityZones"]
        ][:subnet_count]
        if len(azs) < subnet_count:
            raise AssertionError(f"region {ctx.region} exposes only {len(azs)} usable AZs, need {subnet_count}")
        for i, az in enumerate(azs):
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.91.{i}.0/24", AvailabilityZone=az
            )["Subnet"]["SubnetId"]
            subnet_ids.append(subnet_id)
            ctx.on_cleanup(lambda s=subnet_id: _safe_delete_subnet(ctx, s))
            ec2.create_tags(Resources=[subnet_id], Tags=TAGS_KV)
    else:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
        if not vpcs:
            raise AssertionError("cannot create a VPC and no shared network VPC exists to borrow")
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
        if len(subnets) < subnet_count:
            raise AssertionError(f"shared network {vpc_id} has fewer than {subnet_count} subnets available")
        subnet_ids = [s["SubnetId"] for s in subnets[:subnet_count]]

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-r53r-sg-"),
        Description="route53resolver e2e forwarding lifecycle test sg",
    )["GroupId"]
    ctx.on_cleanup(lambda s=sg_id: _safe_delete_sg(ctx, s))
    ec2.create_tags(Resources=[sg_id], Tags=TAGS_KV)

    return vpc_id, subnet_ids, sg_id, owns_network


def _retry_delete(fn, *, timeout_s: float, interval_s: float = 5.0) -> None:
    """Retry a delete while AWS still detaches a dependency (e.g. an asynchronously released ENI).
    NotFound ends it; other errors retry until the deadline, then are swallowed."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            if "NotFound" in exc.response.get("Error", {}).get("Code", ""):
                return
        except Exception:
            pass
        time.sleep(interval_s)
    try:
        fn()
    except Exception:
        pass


def _cleanup_net(ctx: Any, op: str, not_found: str, **ident) -> None:
    """Teardown delete: only the resource's EC2 not-found code ends it quietly; anything else raises."""
    try:
        _delete_net(ctx.client("ec2"), op, **ident)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != not_found:
            raise


def _safe_delete_vpc(ctx: Any, vpc_id: str) -> None:
    _cleanup_net(ctx, "delete_vpc", "InvalidVpcID.NotFound", VpcId=vpc_id)


def _safe_delete_subnet(ctx: Any, subnet_id: str) -> None:
    _cleanup_net(ctx, "delete_subnet", "InvalidSubnetID.NotFound", SubnetId=subnet_id)


def _safe_delete_sg(ctx: Any, sg_id: str) -> None:
    _cleanup_net(ctx, "delete_security_group", "InvalidGroup.NotFound", GroupId=sg_id)


def _safe_delete_endpoint(ctx: Any, endpoint_id: str) -> None:
    try:
        ctx.client("route53resolver").delete_resolver_endpoint(ResolverEndpointId=endpoint_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_rule(ctx: Any, rule_id: str) -> None:
    try:
        ctx.client("route53resolver").delete_resolver_rule(ResolverRuleId=rule_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_rule_assoc_or_none(ctx: Any, assoc_id: str) -> dict | None:
    try:
        return ctx.client("route53resolver").get_resolver_rule_association(
            ResolverRuleAssociationId=assoc_id
        )["ResolverRuleAssociation"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _get_rule_or_none(ctx: Any, rule_id: str) -> dict | None:
    try:
        return ctx.client("route53resolver").get_resolver_rule(ResolverRuleId=rule_id)[
            "ResolverRule"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _get_endpoint_or_none(ctx: Any, endpoint_id: str) -> dict | None:
    try:
        return ctx.client("route53resolver").get_resolver_endpoint(
            ResolverEndpointId=endpoint_id
        )["ResolverEndpoint"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _get_sg_or_none(ctx: Any, sg_id: str) -> dict | None:
    try:
        groups = ctx.client("ec2").describe_security_groups(GroupIds=[sg_id])["SecurityGroups"]
        return groups[0] if groups else None
    except ClientError as exc:
        if "InvalidGroup.NotFound" in exc.response.get("Error", {}).get("Code", ""):
            return None
        raise


def _get_subnet_or_none(ctx: Any, subnet_id: str) -> dict | None:
    try:
        subnets = ctx.client("ec2").describe_subnets(SubnetIds=[subnet_id])["Subnets"]
        return subnets[0] if subnets else None
    except ClientError as exc:
        if "InvalidSubnetID.NotFound" in exc.response.get("Error", {}).get("Code", ""):
            return None
        raise


def _get_vpc_or_none(ctx: Any, vpc_id: str) -> dict | None:
    try:
        vpcs = ctx.client("ec2").describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
        return vpcs[0] if vpcs else None
    except ClientError as exc:
        if "InvalidVpcID.NotFound" in exc.response.get("Error", {}).get("Code", ""):
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. Resources in this VPC
# delete asynchronously and their ENIs linger in the subnet / security group, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for
# the ENIs to go, retry DependencyViolation in the same window, then raise naming the ENIs still
# attached. The window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
