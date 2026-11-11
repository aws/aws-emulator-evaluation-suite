"""modify-capacity-reservation-invalid-unit-count-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-capacity-reservation-invalid-unit-count-rejected"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


_NOT_PERMITTED = (
    "This AWS account does not support configuring minimum load balancer capacity reservation. "
    "For more information, please contact AWS Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Without the capacity-reservation entitlement, ModifyCapacityReservation rejects both -5
    and 100 LCU with OperationNotPermitted (not CapacityUnitsLimitExceeded) and stores no
    reservation, while AddTags on the same load balancer still succeeds.
    """
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)

    lb = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-behav-lb-"),
        Subnets=subnet_ids,
        Scheme="internal",
        Type="application",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    # Positive control: the rejection below is specific to capacity reservations.
    elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": "sim2real-probe", "Value": "healthy"}])
    tags_now = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0]["Tags"]
    assert {"Key": "sim2real-probe", "Value": "healthy"} in tags_now, tags_now

    def _modify(units: int) -> tuple[str, str]:
        def _call():
            return elbv2.modify_capacity_reservation(
                LoadBalancerArn=lb_arn,
                MinimumLoadBalancerCapacity={"CapacityUnits": units},
            )

        return _error(_call)

    # CapacityUnitsLimitExceeded is only for exceeding the account's own maximum.
    negative_code, negative_message = _modify(-5)
    assert negative_code == "OperationNotPermitted", f"expected OperationNotPermitted, got {negative_code}"
    assert negative_code != "CapacityUnitsLimitExceeded"
    assert negative_message == _NOT_PERMITTED, (
        f"expected an entitlement-gate message, got {negative_message!r}"
    )

    # The documented 100 LCU minimum is otherwise valid: the entitlement gate is not a range check.
    valid_code, valid_message = _modify(100)
    assert valid_code == "OperationNotPermitted", f"expected OperationNotPermitted, got {valid_code}"
    assert valid_message == _NOT_PERMITTED, (
        f"expected an entitlement-gate message, got {valid_message!r}"
    )

    after = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert after.get("MinimumLoadBalancerCapacity") is None, (
        f"expected no capacity reservation, got {after.get('MinimumLoadBalancerCapacity')}"
    )
    assert not after.get("CapacityReservationState"), after


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_vpc_with_subnets(ctx: Any) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.107.0.0/16",
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
            CidrBlock=f"10.107.{idx}.0/24",
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


# Resources in this VPC (load balancers, endpoints, functions, ...) delete asynchronously and
# leave ENIs behind, so network deletes answer DependencyViolation for a while. Wait, bounded,
# for those ENIs to go, then raise naming any still attached. The window is shared by all of a
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
