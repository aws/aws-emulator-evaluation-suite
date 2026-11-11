"""concurrent-resolver-rule-association-same-vpc-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-resolver-rule-association-same-vpc-race"
GROUP = "concurrency"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrently associating two different resolver rules to the same VPC resolves
    without a corrupted or duplicated entry in ListResolverRuleAssociations: both
    associations land, each pointing at its own rule, with no phantom duplicates."""
    r53r = ctx.client("route53resolver")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    sg_id = _default_security_group(ctx, vpc_id)
    endpoint_id = _create_outbound_endpoint(ctx, subnet_ids, sg_id)

    rule_a_id = _create_forward_rule(
        ctx, endpoint_id, domain=f"{ctx.unique_name('sim2real-r53r-race-a-')}.test."
    )
    rule_b_id = _create_forward_rule(
        ctx, endpoint_id, domain=f"{ctx.unique_name('sim2real-r53r-race-b-')}.test."
    )

    def _associate(rule_id: str) -> dict[str, Any]:
        return r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)["ResolverRuleAssociation"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_associate, rule_a_id)
        fut_b = pool.submit(_associate, rule_b_id)
        assoc_a = fut_a.result()
        assoc_b = fut_b.result()

    ctx.on_cleanup(lambda: r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_a_id))
    ctx.on_cleanup(lambda: r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_b_id))

    assert assoc_a["Id"] != assoc_b["Id"], "the two racing associations must not collapse into one entry"

    # The VPC may also carry unrelated associations (e.g. the autodefined internet-resolver
    # rule), so only the two rules created here are considered.
    our_rule_ids = {rule_a_id, rule_b_id}

    def _both_present() -> list[dict[str, Any]]:
        assocs = _list_assocs_for_vpc(r53r, vpc_id)
        return [
            a
            for a in assocs
            if a["Status"] != "DELETING" and a["ResolverRuleId"] in our_rule_ids
        ]

    final = _poll_until(
        _both_present,
        lambda assocs: len(assocs) >= 2,
        timeout_s=60.0,
        interval_s=2.0,
    )

    rule_ids_seen = [a["ResolverRuleId"] for a in final]
    assert sorted(rule_ids_seen) == sorted([rule_a_id, rule_b_id]), (
        f"expected exactly one association per rule, got {rule_ids_seen}"
    )
    assert len(rule_ids_seen) == len(set(rule_ids_seen)), "no rule should have a duplicated association"
    assoc_ids_seen = {a["Id"] for a in final}
    assert assoc_ids_seen == {assoc_a["Id"], assoc_b["Id"]}, (
        f"expected association ids {{assoc_a['Id'], assoc_b['Id']}}, got {assoc_ids_seen}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_vpc_with_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    resp = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-r53r-vpc-")}],
            }
        ],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs[:2]]
    subnet_ids = []
    for i, az_name in enumerate(az_names):
        sresp = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.88.{i}.0/24",
            AvailabilityZone=az_name,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-r53r-subnet-")}],
                }
            ],
        )
        subnet_id = sresp["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _default_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )
    return resp["SecurityGroups"][0]["GroupId"]


def _create_outbound_endpoint(ctx, subnet_ids: list[str], sg_id: str) -> str:
    r53r = ctx.client("route53resolver")
    endpoint = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-ep-crid-"),
        Name=ctx.unique_name("sim2real-r53r-ep-"),
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": subnet_ids[0]}, {"SubnetId": subnet_ids[1]}],
    )["ResolverEndpoint"]
    endpoint_id = endpoint["Id"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id))
    _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"]["Status"],
        lambda status: status in ("OPERATIONAL", "ACTION_NEEDED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    return endpoint_id


def _create_forward_rule(ctx, endpoint_id: str, domain: str) -> str:
    r53r = ctx.client("route53resolver")
    rule = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-rule-crid-"),
        Name=ctx.unique_name("sim2real-r53r-rule-"),
        RuleType="FORWARD",
        DomainName=domain,
        ResolverEndpointId=endpoint_id,
        TargetIps=[{"Ip": "10.0.0.2", "Port": 53}],
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_id))
    return rule_id


def _list_assocs_for_vpc(r53r, vpc_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {}
        if token:
            kwargs["NextToken"] = token
        resp = r53r.list_resolver_rule_associations(**kwargs)
        for a in resp.get("ResolverRuleAssociations", []):
            if a.get("VPCId") == vpc_id:
                out.append(a)
        token = resp.get("NextToken")
        if not token:
            break
    return out


# Asynchronously deleted resources leave AWS-managed ENIs in the VPC for a while, so an immediate
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
