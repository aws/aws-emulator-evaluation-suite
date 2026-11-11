"""op-contract-modify-vpc-endpoint-service-configuration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-endpoint-service-configuration"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcEndpointServiceConfiguration: success flips AcceptanceRequired on a
    service backed by a real Network Load Balancer and the change is visible via
    DescribeVpcEndpointServiceConfigurations; DryRun is rejected."""
    ec2 = ctx.client("ec2")

    svc = _create_nlb_backed_service(ctx)
    initial = _describe_service(ec2, svc["service_id"])
    assert initial["AcceptanceRequired"] is False, initial

    # error boundary: DryRun must reject without mutating the configuration.
    err, err_message = _error(
        lambda: ec2.modify_vpc_endpoint_service_configuration(
            ServiceId=svc["service_id"], AcceptanceRequired=True, DryRun=True
        )
    )
    assert err == "DryRunOperation", err
    assert err_message == "Request would have succeeded, but DryRun flag is set.", err_message
    still_initial = _describe_service(ec2, svc["service_id"])
    assert still_initial["AcceptanceRequired"] is False, still_initial

    # success path: require manual acceptance for new endpoint connections.
    resp = ec2.modify_vpc_endpoint_service_configuration(ServiceId=svc["service_id"], AcceptanceRequired=True)
    # Real AWS's boolean confirmation field for this operation (matching the
    # convention used across the rest of the EC2 Modify* surface — e.g.
    # ModifyVpcTenancy, ModifyVpcEndpoint) is "Return", not "ReturnValue".
    assert resp["Return"] is True, resp

    updated = _poll_until(
        lambda: _describe_service(ec2, svc["service_id"]),
        lambda s: s is not None and s.get("AcceptanceRequired") is True,
        timeout_s=60,
        interval_s=5,
    )
    assert updated is not None and updated["AcceptanceRequired"] is True, updated


def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _short_name(ctx, prefix):
    name = ctx.unique_name(f"{prefix}-")[:32]
    while name.endswith("-"):
        name = name[:-1]
    return name


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _describe_service(ec2, service_id):
    resp = ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])
    items = resp.get("ServiceConfigurations", [])
    return items[0] if items else None


def _nlb_exists(elbv2, nlb_arn):
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])
        return True
    except elbv2.exceptions.LoadBalancerNotFoundException:
        return False


def _wait_for_nlb_active(elbv2, nlb_arn, timeout_s=180.0, interval_s=10.0):
    def _describe():
        resp = elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])
        lbs = resp.get("LoadBalancers", [])
        return lbs[0] if lbs else None

    return _poll_until(
        _describe,
        lambda lb: lb is not None and lb.get("State", {}).get("Code") == "active",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _subnet_enis_cleared(ec2, subnet_id):
    resp = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])
    return len(resp.get("NetworkInterfaces", [])) == 0


def _create_vpc_with_retry(ec2, timeout_s=900.0, interval_s=20.0, **kwargs):
    # The account's VPC limit is shared across every check in this suite (several
    # of which each provision their own throwaway VPC), so it is routinely
    # exhausted transiently by sibling checks running concurrently that haven't
    # finished tearing down their own VPCs yet. A sibling can legitimately hold
    # its VPC for several minutes end-to-end (provisioning + assertions + its
    # own bounded polls) before releasing it, so a short retry window gives up
    # too early on real AWS — widen it enough to realistically outlast a
    # sibling's full lifecycle rather than just a brief blip.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)["Vpc"]["VpcId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "VpcLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_with_retry(fn, transient_code, timeout_s=180.0, interval_s=10.0):
    # Deleting a resource whose dependents were JUST deleted (e.g. an NLB's
    # backing ENIs, a VPC endpoint's ENIs) can transiently hit
    # DependencyViolation for a short window before those dependents fully
    # release — retry through that window instead of letting a single failed
    # attempt silently leak the resource (the runner swallows cleanup
    # exceptions), which would otherwise permanently eat into the account's
    # shared quota.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == transient_code and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_nlb_backed_service(ctx):
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    vpc_id = _create_vpc_with_retry(ec2, CidrBlock="10.211.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "svc-vpc"))
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id), "DependencyViolation"))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.211.1.0/24", TagSpecifications=_tag_spec(ctx, "subnet", "svc-subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id), "DependencyViolation"))

    nlb_arn = elbv2.create_load_balancer(
        Name=_short_name(ctx, "sim2realnlb"), Type="network", Scheme="internal", Subnets=[subnet_id]
    )["LoadBalancers"][0]["LoadBalancerArn"]

    def _cleanup_nlb():
        elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
        _poll_until(lambda: _nlb_exists(elbv2, nlb_arn), lambda exists: not exists, timeout_s=180, interval_s=10)
        # An NLB's backing ENIs in its subnet(s) are released asynchronously and
        # routinely outlive the load balancer object itself being reported gone —
        # a subnet/VPC delete issued right after can transiently hit
        # DependencyViolation. Wait for the subnet to actually be clear of ENIs
        # before returning, so the subnet/VPC cleanups below don't race it.
        _poll_until(lambda: _subnet_enis_cleared(ec2, subnet_id), lambda cleared: cleared, timeout_s=180, interval_s=10)

    ctx.on_cleanup(_cleanup_nlb)

    # A freshly created NLB is not immediately usable as a VPC endpoint service
    # backend on real AWS — it starts in "provisioning" and CreateVpcEndpointServiceConfiguration
    # rejects it with InvalidParameter until it reaches "active".
    _wait_for_nlb_active(elbv2, nlb_arn)

    svc = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=False,
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint-service", "svc-cfg"),
    )["ServiceConfiguration"]
    service_id = svc["ServiceId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))

    return {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "nlb_arn": nlb_arn,
        "service_id": service_id,
        "service_name": svc["ServiceName"],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
