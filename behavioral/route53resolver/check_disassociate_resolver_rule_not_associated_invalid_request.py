"""disassociate-resolver-rule-not-associated-invalid-request."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-resolver-rule-not-associated-invalid-request"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateResolverRule on a real rule and VPC that were never associated fails with
    ResourceNotFoundException, not a no-op success; after a real association it succeeds.
    """
    r53r = ctx.client("route53resolver")
    ctx.client("ec2")

    vpc_id, vpc_owned = _create_vpc(ctx)
    endpoint_id = _create_outbound_endpoint(ctx, vpc_id, vpc_owned)

    rule = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        RuleType="FORWARD",
        DomainName=f"{ctx.unique_name('sim2real-behav')}.example.com",
        TargetIps=[{"Ip": "10.0.0.1"}],
        ResolverEndpointId=endpoint_id,
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_id))

    code, message = _expect_error(
        lambda: r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = (
        f'[RSLVR-00800] Resolver Rule Association between Resolver Rule "{rule_id}" and VPC '
        f'"{vpc_id}" does not exist.'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    assoc = r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)["ResolverRuleAssociation"]
    assoc_id = assoc["Id"]
    _wait_for_association_status(ctx, assoc_id, {"COMPLETE", "OVERRIDDEN"})

    r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    _wait_for_association_gone(ctx, assoc_id)


def _expect_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected DisassociateResolverRule to be refused with ResourceNotFoundException, "
        f"but it SUCCEEDED and returned {result!r}"
    )


def _create_vpc(ctx) -> tuple[str, bool]:
    """Return (vpc_id, owned). At the regional VPC quota, adopt the default VPC instead;
    an adopted VPC is never registered for cleanup."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    try:
        vpc = ec2.create_vpc(
            CidrBlock="10.79.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
        )["Vpc"]
    except ClientError as err:
        if err.response["Error"]["Code"] != "VpcLimitExceeded":
            raise
        defaults = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if not defaults:
            raise AssertionError(
                "VPC quota exhausted and no shared network VPC available to adopt"
            ) from err
        return defaults[0]["VpcId"], False
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    return vpc_id, True


def _create_outbound_endpoint(ctx, vpc_id: str, vpc_owned: bool) -> str:
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    subnet_ids = []
    if vpc_owned:
        azs = ec2.describe_availability_zones()["AvailabilityZones"]
        az_names = [az["ZoneName"] for az in azs][:2]
        assert len(az_names) >= 2, "need at least 2 AZs to create a resolver endpoint"
        for i, az in enumerate(az_names):
            subnet = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.79.{i}.0/24", AvailabilityZone=az
            )["Subnet"]
            subnet_id = subnet["SubnetId"]
            ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
            subnet_ids.append(subnet_id)
    else:
        seen_azs = set()
        for sn in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]:
            if sn["AvailabilityZone"] in seen_azs:
                continue
            seen_azs.add(sn["AvailabilityZone"])
            subnet_ids.append(sn["SubnetId"])
            if len(subnet_ids) == 2:
                break
        assert len(subnet_ids) >= 2, (
            f"adopted VPC {vpc_id} has fewer than 2 subnets in distinct AZs"
        )

    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real r53r outbound endpoint sg",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    endpoint = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": sid} for sid in subnet_ids],
    )["ResolverEndpoint"]
    endpoint_id = endpoint["Id"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id))

    import time as _time

    deadline = _time.monotonic() + 180.0
    while _time.monotonic() < deadline:
        cur = r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"]
        if cur["Status"] == "OPERATIONAL":
            return endpoint_id
        if cur["Status"] == "ACTION_NEEDED":
            raise AssertionError(f"resolver endpoint failed to provision: {cur}")
        _time.sleep(5.0)
    raise AssertionError(f"resolver endpoint {endpoint_id} never reached OPERATIONAL")


def _wait_for_association_status(ctx, assoc_id, ok_statuses, timeout_s=300.0):
    r53r = ctx.client("route53resolver")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ]
        if last["Status"] in ok_statuses:
            return last
        time.sleep(1.5)
    raise AssertionError(f"association {assoc_id} never reached {ok_statuses}, last={last}")


def _wait_for_association_gone(ctx, assoc_id, timeout_s=180.0):
    r53r = ctx.client("route53resolver")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
        time.sleep(1.5)
    raise AssertionError(f"association {assoc_id} was never removed")


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
