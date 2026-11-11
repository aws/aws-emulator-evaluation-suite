"""create-load-balancer-invalid-scheme-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-load-balancer-invalid-scheme-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLoadBalancer with an invalid Scheme value is rejected (ValidationError), not
    silently coerced to a default scheme; a valid Scheme in the same VPC/subnets succeeds."""
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)

    bad_name = ctx.unique_name("sim2real-behav-lb-b-")

    def _create_bad() -> None:
        elbv2.create_load_balancer(
            Name=bad_name,
            Subnets=subnet_ids,
            Scheme="not-a-real-scheme",
            Type="application",
        )

    code, message = _error_code(_create_bad)
    # Empirically, real AWS rejects an unrecognized Scheme value with the generic
    # ValidationError (not the InvalidScheme error, which is reserved for a
    # structurally valid scheme that is unsupported for the VPC/subnet configuration).
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "1 validation error detected: Value 'not-a-real-scheme' at 'scheme' failed to satisfy constraint: Member must satisfy enum value set: [internet-facing, internal]"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the load balancer was never created under that name.
    not_found_code, not_found_message = _error_code(lambda: elbv2.describe_load_balancers(Names=[bad_name]))
    assert not_found_code == "LoadBalancerNotFound", (
        f"expected the rejected load balancer to not exist, got {not_found_code}"
    )
    expected_not_found = f"Load balancers '[{bad_name}]' not found"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # Positive control: a valid Scheme value on the same subnets succeeds.
    good_name = ctx.unique_name("sim2real-behav-lb-g-")
    resp = elbv2.create_load_balancer(
        Name=good_name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="application",
    )
    lb = resp["LoadBalancers"][0]
    good_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=good_arn))

    described = elbv2.describe_load_balancers(LoadBalancerArns=[good_arn])["LoadBalancers"][0]
    assert described["Scheme"] == "internal", (
        f"expected the accepted load balancer to be described with Scheme=internal, "
        f"got {described['Scheme']!r}"
    )


# ===== helpers =====

def _error_code(fn) -> tuple[str, str]:
    """Return (code, message) of the ClientError ``fn`` raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_vpc_with_subnets(ctx: Any) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.101.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    assert len(azs) >= 2, "region needs at least 2 available AZs for this check"

    subnet_ids = []
    for idx, az_name in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.101.{idx}.0/24",
            AvailabilityZone=az_name,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}],
            }],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return vpc_id, subnet_ids


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes.
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
