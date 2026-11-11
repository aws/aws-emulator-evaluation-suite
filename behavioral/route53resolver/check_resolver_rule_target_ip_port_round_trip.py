"""resolver-rule-target-ip-port-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resolver-rule-target-ip-port-round-trip"
GROUP = "server-side"
SERVICES = ["route53resolver"]
TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A resolver rule created with multiple TargetIps using non-default port numbers
    returns those exact IP/port pairs unchanged from GetResolverRule -- no truncation,
    no default-port (53) substitution."""
    r53r = ctx.client("route53resolver")
    _, subnet_ids, sg_id = _create_test_network(ctx, ctx.client("ec2"))

    endpoint = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-ep-"),
        Direction="OUTBOUND",
        SecurityGroupIds=[sg_id],
        IpAddresses=[{"SubnetId": s} for s in subnet_ids],
        Tags=TAGS_KV,
    )["ResolverEndpoint"]
    endpoint_id = endpoint["Id"]
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(r53r, endpoint_id))

    endpoint = _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"],
        lambda e: e["Status"] in ("OPERATIONAL", "ACTION_NEEDED"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert endpoint["Status"] == "OPERATIONAL", f"endpoint reached {endpoint['Status']}"

    target_ips = [
        {"Ip": "10.11.12.13", "Port": 5353},
        {"Ip": "10.14.15.16", "Port": 8853},
        {"Ip": "10.17.18.19", "Port": 15353},
    ]

    rule = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-rule-"),
        RuleType="FORWARD",
        DomainName=f"{ctx.unique_name('sim2real-')}.test",
        TargetIps=target_ips,
        ResolverEndpointId=endpoint_id,
        Tags=TAGS_KV,
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule(ctx, rule_id))

    fetched = r53r.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    fetched_ips = fetched["TargetIps"]

    assert len(fetched_ips) == len(target_ips), (
        f"expected {len(target_ips)} target IPs, got {len(fetched_ips)}: {fetched_ips}"
    )
    fetched_pairs = {(t["Ip"], t["Port"]) for t in fetched_ips}
    expected_pairs = {(t["Ip"], t["Port"]) for t in target_ips}
    assert fetched_pairs == expected_pairs, (
        f"target IP/port pairs mismatch: expected {expected_pairs}, got {fetched_pairs}"
    )
    # None of the non-default ports were silently replaced with the DNS default (53).
    assert all(port != 53 for _, port in fetched_pairs), (
        f"a non-default port was replaced with the DNS default 53: {fetched_pairs}"
    )

    r53r.delete_resolver_rule(ResolverRuleId=rule_id)
    _poll_until(
        lambda: _absent(lambda: r53r.get_resolver_rule(ResolverRuleId=rule_id)),
        lambda gone: gone,
        timeout_s=120.0,
        interval_s=5.0,
    )
    deleted = _error(lambda: r53r.get_resolver_rule(ResolverRuleId=rule_id))
    expected = (
        "ResourceNotFoundException",
        f'[RSLVR-00703] Resolver rule with ID "{rule_id}" does not exist.',
    )
    assert deleted == expected, f"expected {expected!r} for the deleted rule, got {deleted!r}"


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{resource_type}-")}],
    }


def _create_test_network(ctx, ec2):
    vpc_id = ec2.create_vpc(
        CidrBlock="10.94.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")]
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
            CidrBlock=f"10.94.{i}.0/24",
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


def _safe_delete_rule(ctx: Any, rule_id: str) -> None:
    try:
        ctx.client("route53resolver").delete_resolver_rule(ResolverRuleId=rule_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

