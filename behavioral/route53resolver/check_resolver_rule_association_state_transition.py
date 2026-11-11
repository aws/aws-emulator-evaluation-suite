"""resolver-rule-association-state-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-rule-association-state-transition"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateResolverRule moves the association to COMPLETE, readable via
    GetResolverRuleAssociation and visible in ListResolverRuleAssociations, and
    DisassociateResolverRule removes it from both views."""
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_id, subnet_ids, sg_id = _create_test_network(ctx, ec2)

    endpoint = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-ep-"),
        Name=ctx.unique_name("sim2real-outbound-"),
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": sid} for sid in subnet_ids],
    )["ResolverEndpoint"]
    endpoint_id = endpoint["Id"]
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(r53r, endpoint_id))

    _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"]["Status"],
        lambda s: s in ("OPERATIONAL", "ACTION_NEEDED"),
        timeout_s=600,
        interval_s=10,
    )
    endpoint_status = r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"]["Status"]
    assert endpoint_status == "OPERATIONAL", (
        f"resolver endpoint expected to reach OPERATIONAL, got {endpoint_status!r}"
    )

    domain = ctx.unique_name("sim2real-domain").replace("_", "-") + ".test"
    rule = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-rule-"),
        Name=ctx.unique_name("sim2real-rule-"),
        RuleType="FORWARD",
        DomainName=domain,
        TargetIps=[{"Ip": "10.0.0.1", "Port": 53}],
        ResolverEndpointId=endpoint_id,
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_id))

    assoc = r53r.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id, Name=ctx.unique_name("sim2real-assoc-")
    )["ResolverRuleAssociation"]
    assoc_id = assoc["Id"]

    status = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ]["Status"],
        lambda s: s in ("COMPLETE", "FAILED", "OVERRIDDEN"),
        timeout_s=120,
        interval_s=5,
    )
    assert status == "COMPLETE", f"association reached {status!r} instead of COMPLETE"

    listed = r53r.list_resolver_rule_associations()["ResolverRuleAssociations"]
    assert any(a["Id"] == assoc_id for a in listed), "association missing from ListResolverRuleAssociations"

    r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    _poll_until(
        lambda: _absent(
            lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
        ),
        lambda gone: gone,
        timeout_s=120,
        interval_s=5,
    )
    gone = _error(lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id))
    expected_gone = (
        "ResourceNotFoundException",
        f'ResolverRuleAssociation "{assoc_id}" does not Exist.',
    )
    assert gone == expected_gone, f"expected {expected_gone!r} after disassociate, got {gone!r}"

    second_disassociate = _error(
        lambda: r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    )
    expected_second = (
        "ResourceNotFoundException",
        f'[RSLVR-00800] Resolver Rule Association between Resolver Rule "{rule_id}" and VPC '
        f'"{vpc_id}" does not exist.',
    )
    assert second_disassociate == expected_second, (
        "disassociating an already-removed rule/VPC pair should raise "
        f"{expected_second!r}, got {second_disassociate!r}"
    )

    remaining = r53r.list_resolver_rule_associations()["ResolverRuleAssociations"]
    assert not any(a["Id"] == assoc_id for a in remaining), "disassociated rule still listed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _absent(fn) -> bool:
    """True once fn() raises ResourceNotFoundException, False while it still succeeds."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{resource_type}-")}],
    }


def _create_test_network(ctx, ec2):
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ][:2]
    assert len(azs) >= 2, "region does not have two available AZs to test with"

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real route53resolver behavioral test sg",
        TagSpecifications=[_tag_spec(ctx, "security-group")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))

    return vpc_id, subnet_ids, sg_id


def _retry_delete(delete_fn, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete_fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("DependencyViolation", "ResourceInUse") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            if code in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound"):
                return
            raise


def _delete_endpoint_and_wait(r53r, endpoint_id, *, timeout_s=300.0, interval_s=10.0):
    try:
        r53r.delete_resolver_endpoint(ResolverEndpointId=endpoint_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _poll_until(
        lambda: _absent(lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)),
        lambda gone: gone,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
