"""op-contract-delete-secondary-network."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-secondary-network"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecondaryNetwork: success transitions to delete-in-progress; DryRun rejects."""

    ec2 = ctx.client("ec2")

    tag_name = ctx.unique_name("sim2real-behav-secnet-")
    try:
        network = ec2.create_secondary_network(
            Ipv4CidrBlock="10.95.0.0/16",
            NetworkType="rdma",
            TagSpecifications=[
                {"ResourceType": "secondary-network", "Tags": [{"Key": "Name", "Value": tag_name}]}
            ],
        )["SecondaryNetwork"]
    except Exception as exc:  # pragma: no cover - feature availability varies by account
        raise AssertionError(f"CreateSecondaryNetwork unavailable: {exc}") from exc

    network_id = network["SecondaryNetworkId"]
    ctx.on_cleanup(lambda: _best_effort_delete_network(ec2, network_id))

    def _describe_state() -> str:
        return ec2.describe_secondary_networks(SecondaryNetworkIds=[network_id])[
            "SecondaryNetworks"
        ][0]["State"]

    _poll_until(_describe_state, lambda state: state == "create-complete", timeout_s=120)

    # Error boundary: DryRun on a valid delete request must short-circuit with DryRunOperation,
    # and the effect must be absent: the network must still be sitting in create-complete.
    code, msg = _client_error(
        lambda: ec2.delete_secondary_network(SecondaryNetworkId=network_id, DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    state_after_dry_run = _describe_state()
    assert state_after_dry_run == "create-complete", (
        f"DryRun must not start deletion, but state is {state_after_dry_run!r}"
    )

    # Success path: real delete transitions state and is eventually reflected as gone.
    resp = ec2.delete_secondary_network(SecondaryNetworkId=network_id)
    assert resp["SecondaryNetwork"]["SecondaryNetworkId"] == network_id, (
        f"delete response SecondaryNetworkId {resp['SecondaryNetwork']['SecondaryNetworkId']!r} "
        f"!= requested {network_id!r}"
    )
    assert resp["SecondaryNetwork"]["State"] in ("delete-in-progress", "delete-complete"), (
        f"expected delete-in-progress or delete-complete right after delete, "
        f"got {resp['SecondaryNetwork']['State']!r}"
    )

    final_state = _poll_until(_describe_state, lambda state: state == "delete-complete", timeout_s=180)
    assert final_state == "delete-complete", f"expected delete-complete, got {final_state!r}"

    # Deletes prove unusable too: a second delete of the same id must not resurrect it or
    # silently succeed as if it were still live. Measured against real AWS: a delete-complete
    # network is rejected as InvalidState, not as a NotFound -- the id keeps describing.
    second_code, second_msg = _client_error(
        lambda: ec2.delete_secondary_network(SecondaryNetworkId=network_id)
    )
    assert second_code == "InvalidState", (
        f"expected a double-delete of a delete-complete network to be rejected as InvalidState, "
        f"got {second_code!r}"
    )
    expected_msg = f"The secondary network '{network_id}' is not in a modifiable state."
    assert second_msg == expected_msg, f"expected message {expected_msg!r}, got {second_msg!r}"
    state_after_double_delete = _describe_state()
    assert state_after_double_delete == "delete-complete", (
        f"a double-delete must not resurrect or otherwise change state; "
        f"got {state_after_double_delete!r}"
    )


def _best_effort_delete_network(ec2: Any, network_id: str) -> None:
    try:
        ec2.delete_secondary_network(SecondaryNetworkId=network_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSecondaryNetworkId.NotFound":
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
