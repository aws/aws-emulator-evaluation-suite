"""list-resolver-rule-associations-stable-ordering."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resolver-rule-associations-stable-ordering"
GROUP = "ordering"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResolverRuleAssociations filtered to one VPC returns the same set of associations
    across repeated calls when nothing changes in between (order is undocumented, so ignored)."""
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")

    vpc_id, subnet_ids, sg_id = _create_networking(ctx, ec2)
    endpoint_id = _create_outbound_endpoint(ctx, r53r, subnet_ids, sg_id)
    rule_ids = [
        _create_forward_rule(ctx, r53r, f"sim2real-r53r-order-{i}.example.", endpoint_id) for i in range(3)
    ]

    for rule_id in rule_ids:
        r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)
        ctx.on_cleanup(lambda rid=rule_id: _safe_disassociate(r53r, rid, vpc_id))

    for rule_id in rule_ids:
        _poll_until(
            lambda rid=rule_id: r53r.list_resolver_rule_associations(
                Filters=[{"Name": "ResolverRuleId", "Values": [rid]}, {"Name": "VPCId", "Values": [vpc_id]}]
            )["ResolverRuleAssociations"],
            lambda assocs: len(assocs) == 1 and assocs[0]["Status"] in ("COMPLETE", "OVERRIDDEN"),
            timeout_s=180,
            interval_s=5,
        )

    def list_associations():
        assocs = r53r.list_resolver_rule_associations(Filters=[{"Name": "VPCId", "Values": [vpc_id]}])[
            "ResolverRuleAssociations"
        ]
        return [a for a in assocs if a["ResolverRuleId"] in rule_ids]

    assocs_1 = list_associations()
    assocs_2 = list_associations()

    assert {a["ResolverRuleId"] for a in assocs_1} == set(rule_ids), (
        f"expected an association for every created rule, "
        f"got {[a['ResolverRuleId'] for a in assocs_1]} vs {rule_ids}"
    )
    assert len(assocs_1) == 3, f"expected 3 associations, got {assocs_1}"
    order_1 = [a["Id"] for a in assocs_1]
    order_2 = [a["Id"] for a in assocs_2]
    assert order_1 == order_2 or sorted(order_1) == sorted(order_2), (
        f"associations changed across calls: {order_1} != {order_2}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _create_networking(ctx, ec2):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i + 1}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name}-subnet-{i}"}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-r53r-sg-"),
        Description="sim2real route53resolver behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": f"{name}-sg"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    return vpc_id, subnet_ids, sg_id


def _create_outbound_endpoint(ctx, r53r, subnet_ids, sg_id):
    endpoint_id = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-cre-"),
        Name=ctx.unique_name("sim2real-endpoint-")[:64],
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": subnet_ids[0]}, {"SubnetId": subnet_ids[1]}],
    )["ResolverEndpoint"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(r53r, endpoint_id))
    _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"],
        lambda e: e["Status"] == "OPERATIONAL",
        timeout_s=300,
        interval_s=5,
    )
    return endpoint_id


def _safe_delete_endpoint(r53r, endpoint_id, timeout_s=180):
    """An endpoint refuses deletion while a rule still references it; retry on that refusal."""
    _retry_in_use(lambda: r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id), timeout_s)


def _retry_in_use(fn, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_forward_rule(ctx, r53r, domain, endpoint_id):
    resp = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crr-"),
        Name=ctx.unique_name("sim2real-rule-")[:64],
        RuleType="FORWARD",
        DomainName=domain,
        TargetIps=[{"Ip": "192.0.2.1", "Port": 53}],
        ResolverEndpointId=endpoint_id,
    )["ResolverRule"]
    rule_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule(r53r, rule_id))
    return rule_id


def _safe_delete_rule(r53r, rule_id, timeout_s=180):
    """A rule refuses deletion while an association is still being removed; retry on that refusal."""
    _retry_in_use(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_id), timeout_s)


def _safe_disassociate(r53r, rule_id, vpc_id, timeout_s=180):
    """Disassociate, then wait until the association is gone: the rule and its endpoint cannot be
    deleted while it is still being removed."""
    try:
        r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _poll_until(
        lambda: r53r.list_resolver_rule_associations(
            Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}, {"Name": "VPCId", "Values": [vpc_id]}]
        )["ResolverRuleAssociations"],
        lambda assocs: assocs == [],
        timeout_s=timeout_s,
        interval_s=2,
    )


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
        _time.sleep(10)
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
        _time.sleep(10)


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
