"""deploy-resolver-rule-cfn-then-associates-successfully."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resolver-rule-cfn-then-associates-successfully"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A ResolverRule deployed via CloudFormation is a working rule: it reads back via
    GetResolverRule, associates to a VPC, and the association reads back correctly."""
    r53r = ctx.client("route53resolver")
    vpc_id, subnet_ids, sg_id = _network(ctx)

    # FORWARD rules with TargetIps require a live outbound Resolver endpoint id --
    # provision it directly (outside the stack) so the CFN template can reference it.
    endpoint = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-ep-"),
        Direction="OUTBOUND",
        SecurityGroupIds=[sg_id],
        IpAddresses=[{"SubnetId": s} for s in subnet_ids],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    rule_name = ctx.unique_name("sim2real-r53r-rule-")
    domain_name = f"{ctx.unique_name('sim2real-')}.test"

    template = json.dumps(
        {
            "Resources": {
                "Rule": {
                    "Type": "AWS::Route53Resolver::ResolverRule",
                    "Properties": {
                        "Name": rule_name,
                        "RuleType": "FORWARD",
                        "DomainName": domain_name,
                        "ResolverEndpointId": endpoint_id,
                        "TargetIps": [{"Ip": "10.0.0.53", "Port": 53}],
                    },
                }
            },
            "Outputs": {"RuleId": {"Value": {"Ref": "Rule"}}},
        }
    )

    stack_name, outputs = _deploy_cfn(ctx, template)
    _register_stack_cleanup(ctx, stack_name)
    rule_id = outputs["RuleId"]


    # Resolver normalizes DomainName to a trailing-dot FQDN form.
    rule = r53r.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    assert rule["DomainName"] in (domain_name, domain_name + "."), (
        f"expected DomainName {domain_name!r} (with or without trailing dot), got {rule['DomainName']!r}"
    )
    assert rule["RuleType"] == "FORWARD", f"expected RuleType FORWARD, got {rule['RuleType']!r}"
    assert rule["Status"] == "COMPLETE", f"expected rule Status COMPLETE, got {rule['Status']!r}"

    assoc = r53r.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id, Name=ctx.unique_name("sim2real-r53r-assoc-")
    )["ResolverRuleAssociation"]
    assoc_id = assoc["Id"]

    def _disassociate() -> None:
        try:
            r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _poll_until(
            lambda: _get_rule_assoc_or_none(ctx, assoc_id),
            lambda v: v is None,
            timeout_s=90.0,
            interval_s=2.0,
        )

    ctx.on_cleanup(_disassociate)

    final_assoc = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final_assoc["Status"] == "COMPLETE", (
        f"expected association Status COMPLETE, got {final_assoc['Status']!r}"
    )
    assert final_assoc["ResolverRuleId"] == rule_id, (
        f"expected association ResolverRuleId {rule_id!r}, got {final_assoc['ResolverRuleId']!r}"
    )
    assert final_assoc["VPCId"] == vpc_id, (
        f"expected association VPCId {vpc_id!r}, got {final_assoc['VPCId']!r}"
    )


def _network(ctx: Any) -> tuple[str, list[str], str]:
    """Adopt the run's shared network if it has >=2 subnets; otherwise create a
    dedicated one. A freshly provisioned account may have no shared network at all."""

    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
        if len(subnets) >= 2:
            groups = ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
            ).get("SecurityGroups", [])
            if groups:
                return vpc_id, [s["SubnetId"] for s in subnets[:2]], groups[0]["GroupId"]
    return _create_network(ctx)


def _create_network(ctx: Any) -> tuple[str, list[str], str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az)[
            "Subnet"
        ]["SubnetId"]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda sid=subnet_id: _safe_delete_subnet(ctx, sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _safe_delete_vpc(ctx: Any, vpc_id: str) -> None:
    _delete_ignoring(lambda: _delete_net(ctx.client("ec2"), "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")


def _safe_delete_subnet(ctx: Any, subnet_id: str) -> None:
    _delete_ignoring(
        lambda: _delete_net(ctx.client("ec2"), "delete_subnet", SubnetId=subnet_id), "InvalidSubnetID.NotFound"
    )


def _safe_delete_endpoint(ctx: Any, endpoint_id: str) -> None:
    _delete_ignoring(
        lambda: ctx.client("route53resolver").delete_resolver_endpoint(ResolverEndpointId=endpoint_id),
        "ResourceNotFoundException",
    )


def _delete_ignoring(delete, not_found_code: str) -> None:
    """Run a teardown delete; an already-gone resource is fine, every other error raises."""
    try:
        delete()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != not_found_code:
            raise


def _deploy_cfn(ctx: Any, template_body: str) -> tuple[str, dict[str, str]]:

    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-r53r-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
    )
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    return stack_name, outputs


def _register_stack_cleanup(ctx: Any, stack_name: str) -> None:
    def _delete() -> None:
        cfn = ctx.client("cloudformation")
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_delete)


def _get_rule_assoc_or_none(ctx: Any, assoc_id: str) -> dict | None:
    from botocore.exceptions import ClientError

    r53r = ctx.client("route53resolver")
    try:
        return r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
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
