"""op-contract-describe-vpc-endpoint-service-configurations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpc-endpoint-service-configurations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcEndpointServiceConfigurations returns the caller's own config by ServiceId,
    lists it among all configs, and rejects a ServiceId that was never allocated.
    """
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.219.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "svc-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.219.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec(ctx, "subnet", "svc-subnet")],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    nlb_name = ctx.unique_name("sim2real-nlb-")[:32].rstrip("-")
    nlb_arn = elbv2.create_load_balancer(
        Name=nlb_name, Subnets=[subnet_id], Scheme="internal", Type="network", IpAddressType="ipv4"
    )["LoadBalancers"][0]["LoadBalancerArn"]

    def _cleanup_nlb() -> None:
        _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn))
        _poll_until(
            lambda: _nlb_state(elbv2, nlb_arn),
            lambda s: s == "gone",
            timeout_s=180.0,
            interval_s=5.0,
            on_timeout="ignore",
        )

    ctx.on_cleanup(_cleanup_nlb)

    # the NLB must be fully provisioned ("active") before it can back a VPC endpoint service
    nlb_state = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert nlb_state == "active", f"NLB never reached 'active' (state={nlb_state!r})"

    service_id = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=True,
        TagSpecifications=[_tag_spec(ctx, "vpc-endpoint-service", "svc")],
    )["ServiceConfiguration"]["ServiceId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))
    )

    # Positive control: describe by the real id must return exactly this config, with the
    # backing NLB attached -- this is what distinguishes "rejects a never-allocated id" from
    # "rejects every id".
    described = ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])[
        "ServiceConfigurations"
    ]
    assert len(described) == 1, f"expected exactly one config for {service_id!r}, got {described!r}"
    config = described[0]
    assert config["ServiceId"] == service_id
    assert nlb_arn in config.get("NetworkLoadBalancerArns", []), config
    assert "Interface" in {t["ServiceType"] for t in config.get("ServiceType", [])}, config

    # The unfiltered list is the caller's own configs and must include what was just created.
    all_configs = ec2.describe_vpc_endpoint_service_configurations()["ServiceConfigurations"]
    assert service_id in {c["ServiceId"] for c in all_configs}, [c["ServiceId"] for c in all_configs]
    for entry in all_configs:
        assert "ServiceId" in entry and "ServiceType" in entry and "ServiceState" in entry

    # Negative: a syntactically well-formed ServiceId that was never allocated is always invalid
    # -- it can never become valid, so there is no restore leg.
    bogus_id = "vpce-svc-00000000000000000"
    code, message = _client_error(
        lambda: ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[bogus_id])
    )
    assert code == "InvalidVpcEndpointServiceId.NotFound", f"expected NotFound, got {code}"
    expected_message = f"The VpcEndpointService Id '{bogus_id}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====

def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _delete_if_present(fn):
    """Run a network delete (which retries DependencyViolation itself); only not-found means gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _nlb_state(elbv2, arn):
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[arn])
        return "present"
    except Exception as exc:  # noqa: BLE001 - broad by design for cleanup polling
        if "LoadBalancerNotFound" in type(exc).__name__ or "LoadBalancerNotFound" in str(exc):
            return "gone"
        return "present"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, on_timeout="raise"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if on_timeout == "ignore":
        return last
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


# EC2 network deletes wait for AWS-managed ENIs to leave: a resource in this VPC deletes asynchronously,
# so DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until its ENIs go. Retry
# that code to one deadline shared by the check's network deletes, then raise naming the ENIs left.
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
