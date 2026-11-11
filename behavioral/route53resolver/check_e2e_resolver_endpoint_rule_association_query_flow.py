"""e2e-resolver-endpoint-rule-association-query-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-resolver-endpoint-rule-association-query-flow"
GROUP = "e2e"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ResolverEndpoint, FORWARD rule and VPC association reach a COMPLETE association with the
    right rule and VPC, and after disassociation and deletion the association, rule and endpoint
    each answer ResourceNotFoundException naming their id.
    """
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-r53r-e2e-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.90.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-r53r-e2e-subnet-{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-r53r-e2e-sg-"),
        Description="sim2real r53r e2e outbound sg",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", ctx.unique_name("sim2real-r53r-e2e-sg-"))],
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))

    endpoint_name = ctx.unique_name("sim2real-r53r-e2e-ep-")[:64]
    endpoint_id = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-ep-req-"),
        Name=endpoint_name,
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": s} for s in subnet_ids],
        Tags=[{"Key": "Name", "Value": endpoint_name}],
    )["ResolverEndpoint"]["Id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id))
    )

    ep_status = _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"][
            "Status"
        ],
        lambda s: s in ("OPERATIONAL", "ACTION_NEEDED", "AUTO_RECOVERING"),
        timeout_s=600,
        interval_s=10,
    )
    assert ep_status == "OPERATIONAL", f"endpoint reached {ep_status}, not OPERATIONAL"

    rule_name = ctx.unique_name("sim2real-r53r-e2e-rule-")[:64]
    rule_id = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-rule-req-"),
        Name=rule_name,
        RuleType="FORWARD",
        DomainName="sim2real-e2e-forward.test.",
        TargetIps=[{"Ip": "10.253.253.253", "Port": 53}],
        ResolverEndpointId=endpoint_id,
        Tags=[{"Key": "Name", "Value": rule_name}],
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda: _delete_rule(r53r, rule_id))

    assoc_id = r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)[
        "ResolverRuleAssociation"
    ]["Id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id))
    )

    assoc_status = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ]["Status"],
        lambda s: s in ("COMPLETE", "FAILED", "OVERRIDDEN"),
        timeout_s=180,
        interval_s=5,
    )
    assert assoc_status == "COMPLETE", f"association reached {assoc_status}, not COMPLETE"

    mid_flow = r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
        "ResolverRuleAssociation"
    ]
    assert mid_flow["ResolverRuleId"] == rule_id, (
        f"association {assoc_id} reports rule {mid_flow['ResolverRuleId']!r}, expected {rule_id!r}"
    )
    assert mid_flow["VPCId"] == vpc_id, (
        f"association {assoc_id} reports VPC {mid_flow['VPCId']!r}, expected {vpc_id!r}"
    )

    r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    gone_code, gone_message = _wait_refused(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id),
        timeout_s=180,
        interval_s=5,
    )
    assert gone_code == "ResourceNotFoundException", (
        f"association {assoc_id} still readable ({gone_code!r}) after disassociate"
    )
    # The message opens with a per-request token, so everything after it is asserted.
    assert gone_message.endswith(f'"{assoc_id}" does not Exist.'), (
        f"expected the not-found message to name association {assoc_id}, got {gone_message!r}"
    )

    r53r.delete_resolver_rule(ResolverRuleId=rule_id)
    rule_gone = _wait_refused(
        lambda: r53r.get_resolver_rule(ResolverRuleId=rule_id),
        timeout_s=120,
        interval_s=5,
    )
    expected = (
        "ResourceNotFoundException",
        f'[RSLVR-00703] Resolver rule with ID "{rule_id}" does not exist.',
    )
    assert rule_gone == expected, (
        f"rule {rule_id} still readable ({rule_gone!r}) after delete, expected {expected!r}"
    )

    r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id)
    ep_gone = _wait_refused(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id),
        timeout_s=300,
        interval_s=10,
    )
    expected = (
        "ResourceNotFoundException",
        f'[RSLVR-00501] Resolver endpoint with ID "{endpoint_id}" does not exist.',
    )
    assert ep_gone == expected, (
        f"endpoint {endpoint_id} still readable ({ep_gone!r}) after delete, expected {expected!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _wait_refused(fn, *, timeout_s: float, interval_s: float):
    """Retry fn() until AWS refuses it; return the error (code, message); raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"the call still succeeded after {timeout_s}s")
        time.sleep(interval_s)


def _safe(fn) -> None:
    """Run a teardown delete; an already-gone resource is fine, every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise


def _delete_rule(r53r, rule_id: str, timeout_s: float = 180.0) -> None:
    """Teardown DeleteResolverRule: retry ResourceInUseException while a disassociation settles,
    then raise; not-found ends it, every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.delete_resolver_rule(ResolverRuleId=rule_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
