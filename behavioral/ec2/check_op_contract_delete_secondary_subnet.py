"""op-contract-delete-secondary-subnet."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-secondary-subnet"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecondarySubnet: success transitions to delete-in-progress; DryRun rejects."""

    ec2 = ctx.client("ec2")

    try:
        network = ec2.create_secondary_network(
            Ipv4CidrBlock="10.96.0.0/16",
            NetworkType="rdma",
            TagSpecifications=[
                {
                    "ResourceType": "secondary-network",
                    "Tags": [{"Key": "sim2real-check", "Value": "delete-secondary-subnet-contract"}],
                }
            ],
        )["SecondaryNetwork"]
    except Exception as exc:  # pragma: no cover - feature availability varies by account
        raise AssertionError(f"CreateSecondaryNetwork unavailable: {exc}") from exc

    network_id = network["SecondaryNetworkId"]
    ctx.on_cleanup(lambda: _best_effort_delete_network(ec2, network_id))

    _poll_until(
        lambda: ec2.describe_secondary_networks(SecondaryNetworkIds=[network_id])[
            "SecondaryNetworks"
        ][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=120,
    )

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]

    try:
        subnet = ec2.create_secondary_subnet(
            SecondaryNetworkId=network_id,
            Ipv4CidrBlock="10.96.0.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "secondary-subnet",
                    "Tags": [{"Key": "sim2real-check", "Value": "delete-secondary-subnet-contract"}],
                }
            ],
        )["SecondarySubnet"]
    except Exception as exc:  # pragma: no cover - feature availability varies by account
        raise AssertionError(f"CreateSecondarySubnet unavailable: {exc}") from exc

    subnet_id = subnet["SecondarySubnetId"]
    ctx.on_cleanup(lambda: _best_effort_delete_subnet(ec2, subnet_id))

    _poll_until(
        lambda: ec2.describe_secondary_subnets(SecondarySubnetIds=[subnet_id])[
            "SecondarySubnets"
        ][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=120,
    )

    # Error boundary: DryRun on a valid delete request must short-circuit with DryRunOperation.
    code, msg = _client_error(
        lambda: ec2.delete_secondary_subnet(SecondarySubnetId=subnet_id, DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect-absent: the dry run must not have mutated anything -- an independent read still
    # shows the subnet exactly where it was before the dry run.
    post_dryrun_state = ec2.describe_secondary_subnets(SecondarySubnetIds=[subnet_id])[
        "SecondarySubnets"
    ][0]["State"]
    assert post_dryrun_state == "create-complete", (
        f"DryRun=True must not mutate state; expected 'create-complete' after the dry run, "
        f"got {post_dryrun_state!r}"
    )

    # Success path: real delete transitions state and is eventually reflected as gone.
    resp = ec2.delete_secondary_subnet(SecondarySubnetId=subnet_id)
    assert resp["SecondarySubnet"]["SecondarySubnetId"] == subnet_id, (
        f"expected the delete response to echo SecondarySubnetId {subnet_id!r}, "
        f"got {resp['SecondarySubnet']['SecondarySubnetId']!r}"
    )
    assert resp["SecondarySubnet"]["State"] in ("delete-in-progress", "delete-complete"), (
        f"expected delete response state in ('delete-in-progress', 'delete-complete'), "
        f"got {resp['SecondarySubnet']['State']!r}"
    )

    final_state = _poll_until(
        lambda: ec2.describe_secondary_subnets(SecondarySubnetIds=[subnet_id])[
            "SecondarySubnets"
        ][0]["State"],
        lambda state: state == "delete-complete",
        timeout_s=180,
    )
    assert final_state == "delete-complete", (
        f"expected the secondary subnet to reach 'delete-complete', got {final_state!r}"
    )

    # Deletes prove gone and unusable: a mutation on the now-dead id must also fail. The
    # subnet record persists in 'delete-complete' rather than being purged, so a second
    # delete is rejected as InvalidState, not a NotFound.
    second_delete_code, second_delete_msg = _client_error(
        lambda: ec2.delete_secondary_subnet(SecondarySubnetId=subnet_id)
    )
    assert second_delete_code == "InvalidState", (
        f"deleting an already-deleted secondary subnet should return 'InvalidState', "
        f"got {second_delete_code!r}"
    )
    expected_msg = f"The secondary subnet '{subnet_id}' is not in a modifiable state."
    assert second_delete_msg == expected_msg, (
        f"expected message {expected_msg!r}, got {second_delete_msg!r}"
    )


def _best_effort_delete_network(ec2: Any, network_id: str) -> None:
    try:
        ec2.delete_secondary_network(SecondaryNetworkId=network_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSecondaryNetworkId.NotFound":
            raise


def _best_effort_delete_subnet(ec2: Any, subnet_id: str) -> None:
    try:
        ec2.delete_secondary_subnet(SecondarySubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSecondarySubnetId.NotFound":
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception:
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
