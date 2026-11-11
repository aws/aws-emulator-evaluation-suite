"""op-contract-delete-subnet."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-subnet"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSubnet succeeds on an empty subnet; fails DependencyViolation while an ENI
    still lives in it, and NotFound afterwards confirms the subnet is truly gone."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _tag(ec2, vpc_id, ctx.unique_name("sim2real-behav-subnet-vpc-"))

    # Error boundary first: a subnet with a live ENI cannot be deleted.
    busy_subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.97.1.0/24")["Subnet"][
        "SubnetId"
    ]
    _tag(ec2, busy_subnet_id, ctx.unique_name("sim2real-behav-subnet-"))
    eni_id = ec2.create_network_interface(SubnetId=busy_subnet_id)["NetworkInterface"][
        "NetworkInterfaceId"
    ]
    _tag(ec2, eni_id, ctx.unique_name("sim2real-behav-subnet-eni-"))

    def _cleanup_busy() -> None:
        try:
            ec2.delete_network_interface(NetworkInterfaceId=eni_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
                raise
        try:
            ec2.delete_subnet(SubnetId=busy_subnet_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_busy)

    code, msg = _client_error(lambda: ec2.delete_subnet(SubnetId=busy_subnet_id))
    assert code == "DependencyViolation", f"expected DependencyViolation, got {code!r}"
    expected_msg = f"The subnet '{busy_subnet_id}' has dependencies and cannot be deleted."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The refused delete must not have taken effect: an independent read still finds the subnet.
    still = ec2.describe_subnets(SubnetIds=[busy_subnet_id])["Subnets"][0]
    assert still["SubnetId"] == busy_subnet_id, (
        f"expected subnet {busy_subnet_id!r} to survive the refused delete, "
        f"got {still['SubnetId']!r}"
    )

    ec2.delete_network_interface(NetworkInterfaceId=eni_id)

    # Success path: once the ENI is gone, the identical delete call succeeds.
    resp = _poll_until(
        lambda: _try_delete_subnet(ec2, busy_subnet_id),
        lambda ok: ok is True,
        timeout_s=30,
    )
    assert resp is True, f"expected delete_subnet to succeed once unblocked, got {resp!r}"

    code, msg = _client_error(lambda: ec2.describe_subnets(SubnetIds=[busy_subnet_id]))
    assert code == "InvalidSubnetID.NotFound", f"expected NotFound, got {code!r}"
    expected_msg = f"The subnet ID '{busy_subnet_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Distinct not-found boundary: deleting the same subnet a second time.
    code, msg = _client_error(lambda: ec2.delete_subnet(SubnetId=busy_subnet_id))
    assert code == "InvalidSubnetID.NotFound", f"expected NotFound, got {code!r}"
    expected_msg = f"The subnet ID '{busy_subnet_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _tag(ec2: Any, resource_id: str, name: str) -> None:
    ec2.create_tags(Resources=[resource_id], Tags=[{"Key": "Name", "Value": name}])


def _try_delete_subnet(ec2: Any, subnet_id: str) -> bool:
    try:
        ec2.delete_subnet(SubnetId=subnet_id)
        return True
    except Exception:
        return False


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
