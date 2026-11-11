"""unicode-tag-value-round-trip."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unicode-tag-value-round-trip"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """Tagging a resolver rule with unicode/emoji key-value pairs and reading them back
    via ListTagsForResource yields byte-for-byte identical strings."""
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")
    subnet_ids, sg_id = _create_networking(ctx, ec2)

    endpoint = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-ep-"),
        Direction="OUTBOUND",
        SecurityGroupIds=[sg_id],
        IpAddresses=[{"SubnetId": s} for s in subnet_ids],
    )["ResolverEndpoint"]
    endpoint_id = endpoint["Id"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(ctx, endpoint_id))

    endpoint = _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"],
        lambda e: e["Status"] in ("OPERATIONAL", "ACTION_NEEDED"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert endpoint["Status"] == "OPERATIONAL", f"endpoint reached {endpoint['Status']}"

    rule = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-rule-"),
        RuleType="FORWARD",
        DomainName=f"{ctx.unique_name('sim2real-')}.test",
        TargetIps=[{"Ip": "10.0.0.53", "Port": 53}],
        ResolverEndpointId=endpoint_id,
    )["ResolverRule"]
    rule_id = rule["Id"]
    rule_arn = rule["Arn"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_id))

    unicode_key = "名前-key"
    unicode_value = "café-日本語-value"

    r53r.tag_resource(ResourceArn=rule_arn, Tags=[{"Key": unicode_key, "Value": unicode_value}])

    tags = r53r.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]
    matches = [t for t in tags if t["Key"] == unicode_key]
    assert len(matches) == 1, f"expected exactly one tag with key {unicode_key!r}, got {tags}"
    assert matches[0]["Value"] == unicode_value, (
        f"tag value round-trip mismatch: sent {unicode_value!r}, got {matches[0]['Value']!r}"
    )


def _create_networking(ctx: Any, ec2: Any) -> tuple[list[str], str]:
    """Adopt the default VPC's subnets/security-group when there's a usable default (the
    common case, and it avoids spending one of the account's limited VPC slots); only
    provision a fresh VPC when no default VPC exists, so the check works on a freshly
    provisioned account too."""
    adopted = _adopt_default_vpc(ec2, ctx=ctx)
    if adopted is not None:
        return adopted

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
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name}-subnet-{i}"}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-r53r-sg-"),
        Description="sim2real route53resolver behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": f"{name}-sg"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    return subnet_ids, sg_id


def _adopt_default_vpc(ec2: Any, *, ctx) -> tuple[list[str], str] | None:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if len(subnets) < 2:
        return None
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]

    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not groups:
        return None

    return subnet_ids, groups[0]["GroupId"]


def _safe_delete_endpoint(ctx: Any, endpoint_id: str) -> None:
    try:
        ctx.client("route53resolver").delete_resolver_endpoint(ResolverEndpointId=endpoint_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
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


# AWS-managed ENIs (load balancers, endpoints, functions, ...) leave asynchronously after their
# owner's delete, so network deletes retry DependencyViolation within one bounded shared window.
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

