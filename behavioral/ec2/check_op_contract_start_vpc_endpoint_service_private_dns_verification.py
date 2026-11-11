"""op-contract-start-vpc-endpoint-service-private-dns-verification."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-start-vpc-endpoint-service-private-dns-verification"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartVpcEndpointServicePrivateDnsVerification flips a private DNS config out of
    pendingVerification for a real endpoint service; bogus ServiceId is rejected."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    # Use the account's default VPC and its pre-existing default subnets rather than
    # creating a new VPC: the VPC quota is a small, shared, account-wide limit, and
    # creating a fresh VPC per check risks VpcLimitExceeded (observed on real EC2)
    # when other checks/resources are concurrently holding VPCs. The default
    # VPC/subnets already exist and need no teardown.
    vpc_id, subnet_ids = _default_vpc_subnets(ec2, count=2, ctx=ctx)

    nlb_name = ctx.unique_name("sim2real-nlb-")[:32]
    nlb_arn = elbv2.create_load_balancer(
        Name=nlb_name, Subnets=subnet_ids, Type="network", Scheme="internal"
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn))
    _wait_nlb_active(ctx, nlb_arn)

    dns_name = f"verify.{ctx.unique_name('sim2real-behav-').lower()}.example.com"
    service_id = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        PrivateDnsName=dns_name,
        AcceptanceRequired=False,
    )["ServiceConfiguration"]["ServiceId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))

    def describe_state():
        resp = ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])
        cfg = resp["ServiceConfigurations"][0]
        return cfg.get("PrivateDnsNameConfiguration", {}).get("State")

    initial_state = describe_state()
    assert initial_state == "pendingVerification", initial_state

    # success path: kick off verification. This operation's response has no
    # output members beyond ResponseMetadata on real EC2 (no "Return" field is
    # returned). On real EC2 this call only *initiates* an asynchronous domain-
    # ownership check performed against the public DNS system for the given
    # PrivateDnsName. Since the domain used here (a subdomain of example.com) is
    # not one we control, we cannot publish the TXT record AWS needs to see, so
    # the verification can legitimately remain "pendingVerification" far beyond
    # any bounded test window without that indicating a bug -- observed on real
    # EC2, the state was still "pendingVerification" after polling for 600s.
    resp = ec2.start_vpc_endpoint_service_private_dns_verification(ServiceId=service_id)
    status_code = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status_code == 200, f"expected 200, got {status_code}"

    # dns_name is an unowned example.com subdomain, so real EC2 cannot have found a TXT
    # record for it -- "verified" would mean domain ownership was established for a name
    # we do not control, which would itself be a bug. This is the full modelled enum
    # (DnsNameState = pendingVerification|verified|failed) minus the value that requires
    # ownership we never grant, so the check still distinguishes a target that fabricates
    # verification from one that does not.
    state_after = describe_state()
    assert state_after in ("pendingVerification", "failed"), state_after

    # error boundary: nonexistent service id. Real EC2 validates the service-id shape
    # (length/charset) before existence, and an all-zero id can be rejected as malformed
    # rather than not-found; derive a same-length/charset id from the real service we
    # just created (by rotating its last hex digit) so the shape is guaranteed valid
    # while the id itself doesn't correspond to any service.
    bogus_id = _mutate_last_hex_char(service_id)
    code, message = _error(
        lambda: ec2.start_vpc_endpoint_service_private_dns_verification(ServiceId=bogus_id)
    )
    assert code == "InvalidVpcEndpointServiceId.NotFound", code
    assert message == f"The VpcEndpointService Id '{bogus_id}' does not exist", (
        f"unexpected InvalidVpcEndpointServiceId.NotFound message {message!r}")


def _default_vpc_subnets(ec2, count=2, *, ctx):
    """Return (default_vpc_id, [subnet_id, ...]) using pre-existing network subnets
    in distinct availability zones, avoiding creation of a new VPC/subnets."""
    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"][0][
        "VpcId"
    ]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    seen_azs = set()
    subnet_ids = []
    for s in subnets:
        if s["AvailabilityZone"] in seen_azs:
            continue
        seen_azs.add(s["AvailabilityZone"])
        subnet_ids.append(s["SubnetId"])
        if len(subnet_ids) == count:
            break
    assert len(subnet_ids) >= count, f"need {count} network subnets in distinct AZs, found {subnet_ids}"
    return vpc_id, subnet_ids


def _mutate_last_hex_char(resource_id: str) -> str:
    prefix, last = resource_id[:-1], resource_id[-1]
    rotated = format((int(last, 16) + 1) % 16, "x")
    return prefix + rotated


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _wait_nlb_active(ctx, nlb_arn, timeout_s=240.0):
    elbv2 = ctx.client("elbv2")

    def probe():
        resp = elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])
        return resp["LoadBalancers"][0]["State"]["Code"]

    return _poll_until(probe, lambda s: s == "active", timeout_s=timeout_s, interval_s=10.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
