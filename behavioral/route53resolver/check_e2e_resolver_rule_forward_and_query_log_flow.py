"""e2e-resolver-rule-forward-and-query-log-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-resolver-rule-forward-and-query-log-flow"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A forwarding rule association reaches COMPLETE/OVERRIDDEN and a query log association ACTIVE;
    after disassociating both in dependency order, neither the rule nor the query log config
    lists any remaining association."""
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")
    logs = ctx.client("logs")

    vpc_id, subnet_ids, sg_id = _create_networking(ctx, ec2)

    endpoint_id = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-cre-"),
        Name=ctx.unique_name("sim2real-endpoint-")[:64],
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": subnet_ids[0]}, {"SubnetId": subnet_ids[1]}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ResolverEndpoint"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(r53r, endpoint_id))
    _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"],
        lambda e: e["Status"] == "OPERATIONAL",
        timeout_s=300,
        interval_s=5,
    )

    rule_id = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crr-"),
        Name=ctx.unique_name("sim2real-rule-")[:64],
        RuleType="FORWARD",
        DomainName="sim2real-r53r-e2e-flow.example.",
        TargetIps=[{"Ip": "192.0.2.1", "Port": 53}],
        ResolverEndpointId=endpoint_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule(r53r, rule_id))

    rule_assoc_id = r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)["ResolverRuleAssociation"][
        "Id"
    ]
    ctx.on_cleanup(lambda: _safe_disassociate_rule(r53r, rule_id, vpc_id))
    rule_final = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=rule_assoc_id)[
            "ResolverRuleAssociation"
        ],
        lambda a: a["Status"] in ("COMPLETE", "OVERRIDDEN", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert rule_final["Status"] in ("COMPLETE", "OVERRIDDEN"), (
        f"expected rule association COMPLETE or OVERRIDDEN, got {rule_final['Status']!r}"
    )

    log_group_name = ctx.unique_name("/sim2real/r53r-e2e-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

    qlog_id = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlogcfg-")[:64],
        DestinationArn=log_group_arn,
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crqlc-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ResolverQueryLogConfig"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_query_log_config(r53r, qlog_id))

    qlog_assoc_id = r53r.associate_resolver_query_log_config(ResolverQueryLogConfigId=qlog_id, ResourceId=vpc_id)[
        "ResolverQueryLogConfigAssociation"
    ]["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate_qlog(r53r, qlog_id, vpc_id))
    qlog_final = _poll_until(
        lambda: r53r.get_resolver_query_log_config_association(ResolverQueryLogConfigAssociationId=qlog_assoc_id)[
            "ResolverQueryLogConfigAssociation"
        ],
        lambda a: a["Status"] in ("ACTIVE", "FAILED", "ACTION_NEEDED"),
        timeout_s=120,
        interval_s=3,
    )
    assert qlog_final["Status"] == "ACTIVE", f"expected query log association ACTIVE, got {qlog_final['Status']!r}"

    # Full teardown of the two associations, in the correct order, then confirm nothing
    # dangling is left behind for either.
    r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    _poll_until(
        lambda: _rule_association_gone(r53r, rule_id, vpc_id),
        lambda gone: gone,
        timeout_s=300,
        interval_s=5,
    )
    remaining_rule_assocs = r53r.list_resolver_rule_associations(
        Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}]
    )["ResolverRuleAssociations"]
    assert remaining_rule_assocs == [], f"dangling resolver rule associations: {remaining_rule_assocs}"

    r53r.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=qlog_id, ResourceId=vpc_id)
    _poll_until(
        lambda: _qlog_association_gone(r53r, qlog_id, vpc_id),
        lambda gone: gone,
        timeout_s=300,
        interval_s=5,
    )
    remaining_qlog_assocs = r53r.list_resolver_query_log_config_associations(
        Filters=[{"Name": "ResolverQueryLogConfigId", "Values": [qlog_id]}]
    )["ResolverQueryLogConfigAssociations"]
    assert remaining_qlog_assocs == [], f"dangling query log config associations: {remaining_qlog_assocs}"


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


def _rule_association_gone(r53r, rule_id, vpc_id):
    assocs = r53r.list_resolver_rule_associations(
        Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}, {"Name": "VPCId", "Values": [vpc_id]}]
    )["ResolverRuleAssociations"]
    return len(assocs) == 0


def _qlog_association_gone(r53r, qlog_id, vpc_id):
    assocs = r53r.list_resolver_query_log_config_associations(
        Filters=[{"Name": "ResolverQueryLogConfigId", "Values": [qlog_id]}, {"Name": "ResourceId", "Values": [vpc_id]}]
    )["ResolverQueryLogConfigAssociations"]
    return len(assocs) == 0


def _safe_delete_endpoint(r53r, endpoint_id):
    try:
        r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_rule(r53r, rule_id):
    try:
        r53r.delete_resolver_rule(ResolverRuleId=rule_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_disassociate_rule(r53r, rule_id, vpc_id):
    try:
        r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_disassociate_qlog(r53r, qlog_id, vpc_id):
    try:
        r53r.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=qlog_id, ResourceId=vpc_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_query_log_config(r53r, qlog_id):
    try:
        r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=qlog_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_log_group(logs, log_group_name):
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except logs.exceptions.ResourceNotFoundException:
        pass


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
