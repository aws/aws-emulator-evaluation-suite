"""op-contract-createVpcEndpointServiceConfiguration."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createVpcEndpointServiceConfiguration"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcEndpointServiceConfiguration: success wraps a real Network Load Balancer as an
    Interface-type endpoint service; DryRun short-circuits before any resource is created."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az = azs[0]["ZoneName"]

    vpc_id = _create_vpc(ec2, "10.213.0.0/16", _tag_spec(ctx, "vpc", "svc-vpc"))
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.213.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec(ctx, "subnet", "svc-subnet")],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    nlb_name = ctx.unique_name("sim2real-nlb-")
    nlb_arn = elbv2.create_load_balancer(
        Name=nlb_name, Subnets=[subnet_id], Scheme="internal", Type="network", IpAddressType="ipv4"
    )["LoadBalancers"][0]["LoadBalancerArn"]

    def _cleanup_nlb() -> None:
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise

    ctx.on_cleanup(_cleanup_nlb)

    # A just-created NLB is not immediately usable as an endpoint-service backing resource --
    # referencing its ARN while it is still "provisioning" is rejected as an invalid parameter
    # (the ARN itself is well-formed; it's the load balancer's readiness that's the issue).
    # Poll until it reaches "active" before using it.
    def _nlb_state():
        lbs = elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"]
        return lbs[0]["State"]["Code"] if lbs else "unknown"

    nlb_state = _poll_until(_nlb_state, lambda s: s == "active", timeout_s=180, interval_s=5)
    assert nlb_state == "active", f"NLB never reached 'active' (state={nlb_state!r})"

    # Effect-absent baseline, taken before anything is broken: the DryRun beat below must prove
    # nothing was created, not just that the call returned an error. Only configurations fronting
    # this check's own NLB are counted; other checks create theirs in the same account.
    ids_before_dryrun = _configs_for(ec2, nlb_arn)

    # Error boundary: DryRun must short-circuit before creating the service configuration.
    err = _client_error(
        lambda: ec2.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[nlb_arn], AcceptanceRequired=True, DryRun=True
        )
    )
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    ids_after_dryrun = _configs_for(ec2, nlb_arn)
    assert ids_after_dryrun == ids_before_dryrun, (
        f"DryRun must not create a service configuration: before={ids_before_dryrun!r} "
        f"after={ids_after_dryrun!r}"
    )

    resp = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=True,
        TagSpecifications=[_tag_spec(ctx, "vpc-endpoint-service", "svc")],
    )
    service_id = resp["ServiceConfiguration"]["ServiceId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))

    # Terminal read: an independent DescribeVpcEndpointServiceConfigurations call -- not the
    # CreateVpcEndpointServiceConfiguration response itself -- is what proves the configuration
    # actually persisted the way it was requested.
    described = ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])[
        "ServiceConfigurations"
    ]
    assert len(described) == 1, f"expected exactly one config for {service_id!r}, got {described!r}"
    config = described[0]
    assert nlb_arn in config.get("NetworkLoadBalancerArns", []), config
    assert config["AcceptanceRequired"] is True, config
    service_types = {t["ServiceType"] for t in config.get("ServiceType", [])}
    assert "Interface" in service_types, service_types


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _configs_for(ec2, nlb_arn):
    """Ids of the endpoint service configurations fronting nlb_arn, read through all pages."""
    return {
        c["ServiceId"]
        for page in ec2.get_paginator("describe_vpc_endpoint_service_configurations").paginate()
        for c in page["ServiceConfigurations"]
        if nlb_arn in (c.get("NetworkLoadBalancerArns") or [])
    }


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_delete(fn, attempts: int = 20, delay_s: float = 5.0) -> None:
    """Retry a teardown delete while EC2 still sees a dependent (e.g. an NLB's not-yet-released
    ENI in the same subnet/VPC); anything other than DependencyViolation is not ours to retry."""
    import time

    from botocore.exceptions import ClientError

    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation":
                raise
            time.sleep(delay_s)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_vpc(ec2, cidr_block, tag_spec):
    """Create a VPC, failing loudly if the account has no quota left.

    A quota exhaustion is an environment precondition, not something a check may fix by deleting
    resources it does not own, so `VpcLimitExceeded` propagates.
    """
    return ec2.create_vpc(CidrBlock=cidr_block, TagSpecifications=[tag_spec])["Vpc"]["VpcId"]

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
