"""set-ip-address-type-invalid-subnet-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-ip-address-type-invalid-subnet-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetIpAddressType(dualstack) on subnets lacking an IPv6 CIDR is rejected with ValidationError."""
    subnets = _get_default_subnets(ctx, count=2)
    arn = _create_lb(ctx, subnets["subnet_ids"])
    _wait_lb_active(ctx, arn)

    elbv2 = ctx.client("elbv2")
    initial = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert initial["IpAddressType"] == "ipv4", (
        f"expected the freshly created load balancer to read back as ipv4, "
        f"got {initial['IpAddressType']!r}"
    )

    code, message = _error(
        lambda: elbv2.set_ip_address_type(LoadBalancerArn=arn, IpAddressType="dualstack")
    )
    assert code == "ValidationError", (
        f"expected dualstack on IPv4-only subnets to be rejected with "
        f"ValidationError, got {code!r}"
    )
    expected_message = "You must specify subnets with an associated IPv6 CIDR block."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect-absent: the rejected call must not have moved the load balancer off ipv4,
    # confirmed via an independent read rather than trusting the failed call's own response
    unchanged = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert unchanged["IpAddressType"] == "ipv4", (
        f"expected the rejected call to leave IpAddressType unchanged at ipv4, "
        f"got {unchanged['IpAddressType']!r}"
    )

    # positive control: the same call path, on the same load balancer, accepts a value
    # that IS valid for ipv4-only subnets -- so the rejection above is specific to
    # dualstack-on-ipv4-only-subnets, not evidence that SetIpAddressType rejects everything
    resp = elbv2.set_ip_address_type(LoadBalancerArn=arn, IpAddressType="ipv4")
    assert resp["IpAddressType"] == "ipv4", (
        f"expected re-affirming ipv4 to succeed on the same load balancer, got {resp!r}"
    )
    confirmed = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert confirmed["IpAddressType"] == "ipv4", (
        f"expected IpAddressType to read back as ipv4 after the positive control, "
        f"got {confirmed['IpAddressType']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_default_subnets(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        # Only IPv4-only subnets are useful here (no IPv6 CIDR association).
        if not s.get("Ipv6CidrBlockAssociationSet"):
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = sorted(by_az.values())
    if len(ids) < count:
        raise AssertionError("not enough distinct-AZ IPv4-only subnets in shared network for this check")
    return {"vpc_id": vpc_id, "subnet_ids": ids[:count]}


def _safe_delete_lb(ctx, arn):
    elbv2 = ctx.client("elbv2")
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _create_lb(ctx, subnet_ids, scheme="internal", lb_type="application"):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme=scheme,
        Type=lb_type,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_delete_lb(ctx, arn))
    return arn


def _wait_lb_active(ctx, arn, timeout_s=180.0, interval_s=5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        desc = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
        state = desc["State"]["Code"]
        if state in ("active", "active_impaired", "failed"):
            return state
        time.sleep(interval_s)
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
