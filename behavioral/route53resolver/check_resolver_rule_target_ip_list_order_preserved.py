"""resolver-rule-target-ip-list-order-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "resolver-rule-target-ip-list-order-preserved"
GROUP = "ordering"
SERVICES = ["route53resolver"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s; last observed value: {last!r}")


def _tag_spec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An out-of-order TargetIps list reads back verbatim after CreateResolverRule, and a different
    out-of-order list reads back verbatim after UpdateResolverRule: Resolver tries targets in
    order, so the API must never re-sort them.
    """
    ec2 = ctx.client("ec2")
    r53 = ctx.client("route53resolver")

    name = ctx.unique_name("sim2real-r53res-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16", TagSpecifications=_tag_spec("vpc", name)
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    assert len(azs) == 2, "region does not expose at least two availability zones"

    subnet_ids = []
    for idx, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.77.{idx}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", f"{name}-{idx}"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real route53resolver ordering check", VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group", name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    endpoint = r53.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("cr-"),
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": subnet_ids[0]}, {"SubnetId": subnet_ids[1]}],
    )["ResolverEndpoint"]
    endpoint_id = endpoint["Id"]

    def delete_endpoint_and_wait():
        r53.delete_resolver_endpoint(ResolverEndpointId=endpoint_id)

        def probe():
            try:
                return r53.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"]["Status"]
            except r53.exceptions.ResourceNotFoundException:
                return "GONE"

        _poll_until(probe, lambda s: s == "GONE", timeout_s=300.0, interval_s=10.0)

    ctx.on_cleanup(delete_endpoint_and_wait)

    def get_endpoint_status():
        return r53.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"]["Status"]

    status = _poll_until(
        get_endpoint_status, lambda s: s in ("OPERATIONAL", "ACTION_NEEDED"), timeout_s=600.0, interval_s=15.0
    )
    assert status == "OPERATIONAL", f"resolver endpoint failed to become OPERATIONAL, got {status!r}"

    create_order = [
        {"Ip": "192.0.2.30", "Port": 53},
        {"Ip": "192.0.2.10", "Port": 53},
        {"Ip": "192.0.2.20", "Port": 53},
    ]
    rule = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("cr-"),
        RuleType="FORWARD",
        DomainName=f"{ctx.unique_name('sim2real-domain')}.example.com.",
        ResolverEndpointId=endpoint_id,
        TargetIps=create_order,
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda: r53.delete_resolver_rule(ResolverRuleId=rule_id))

    def target_ips(r):
        return [{"Ip": t["Ip"], "Port": t["Port"]} for t in r["TargetIps"]]

    assert target_ips(rule) == create_order, (
        f"CreateResolverRule response re-ordered TargetIps: sent {create_order!r}, got {target_ips(rule)!r}"
    )

    read_back = r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    assert target_ips(read_back) == create_order, (
        f"GetResolverRule re-ordered TargetIps after create: sent {create_order!r}, got {target_ips(read_back)!r}"
    )

    update_order = [
        {"Ip": "192.0.2.20", "Port": 53},
        {"Ip": "192.0.2.30", "Port": 53},
        {"Ip": "192.0.2.10", "Port": 53},
    ]
    assert update_order != create_order, "update order must differ from create order to be a meaningful check"

    r53.update_resolver_rule(ResolverRuleId=rule_id, Config={"TargetIps": update_order})

    def get_rule():
        return r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]

    updated = _poll_until(get_rule, lambda r: r["Status"] == "COMPLETE", timeout_s=120.0, interval_s=3.0)
    assert target_ips(updated) == update_order, (
        f"GetResolverRule re-ordered TargetIps after update: sent {update_order!r}, got {target_ips(updated)!r}"
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
