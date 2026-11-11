"""resolver-rule-target-ip-port-precision-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-rule-target-ip-port-precision-round-trip"
GROUP = "representation"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TargetIps with non-default port numbers written on CreateResolverRule are returned
    byte-identical (IP + port, including a non-53 port) on GetResolverRule -- not
    silently normalized to port 53 or reordered/dropped."""
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_id = _get_usable_vpc(ec2, ctx=ctx)
    subnet_ids = _get_two_az_subnets(ec2, vpc_id, ctx=ctx)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-r53r-portip-sg-"),
        Description="sim2real r53r target-ip-port precision sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-r53r-portip-sg-")}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_security_group_when_free(ec2, sg_id)))

    endpoint_id = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-portip-ep-req-"),
        Name=ctx.unique_name("sim2real-r53r-portip-ep-")[:64],
        SecurityGroupIds=[sg_id],
        Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": s} for s in subnet_ids],
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

    target_ips = [
        {"Ip": "10.253.11.1", "Port": 5353},
        {"Ip": "10.253.11.2", "Port": 8600},
    ]
    rule_id = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-portip-rule-req-"),
        Name=ctx.unique_name("sim2real-r53r-portip-rule-")[:64],
        RuleType="FORWARD",
        DomainName="sim2real-portip-precision.test.",
        TargetIps=target_ips,
        ResolverEndpointId=endpoint_id,
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_id)))

    fetched = r53r.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    returned_pairs = sorted((t["Ip"], t["Port"]) for t in fetched["TargetIps"])
    expected_pairs = sorted((t["Ip"], t["Port"]) for t in target_ips)
    assert returned_pairs == expected_pairs, (
        f"TargetIps round-trip mismatch: expected {expected_pairs}, got {returned_pairs}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _safe(fn) -> None:
    """Run a teardown delete; an already-gone resource is fine, every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise


def _get_usable_vpc(ec2, *, ctx) -> str:
    """The account's shared network (or, failing that, any existing VPC) -- reused rather than
    creating a fresh one, so this check never touches the account's scarce VPC quota (and,
    since it isn't ours to create, we never delete it either)."""
    default = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if default:
        return default[0]["VpcId"]
    raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")


def _get_two_az_subnets(ec2, vpc_id: str, *, ctx) -> list:
    """Two of the VPC's existing subnets, each in a distinct AZ -- a resolver endpoint
    needs >=2 AZs, and every shared network already has one subnet per AZ, so no new subnet
    (or VPC) needs to be created."""
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    chosen = list(by_az.values())
    assert len(chosen) >= 2, (
        f"VPC {vpc_id} has subnets in only {len(chosen)} AZ(s); a resolver endpoint needs >=2"
    )
    return chosen[:2]



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
