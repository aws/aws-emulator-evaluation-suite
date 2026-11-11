"""op-contract-create-secondary-network."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-secondary-network"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecondaryNetwork: success creates an RDMA secondary network; a CIDR block outside
    the allowed /12-/28 size is rejected."""
    ec2 = ctx.client("ec2")

    resp = ec2.create_secondary_network(
        Ipv4CidrBlock="100.64.0.0/24",
        NetworkType="rdma",
        TagSpecifications=[
            {
                "ResourceType": "secondary-network",
                "Tags": [{"Key": "sim2real-check", "Value": "create-secondary-network-contract"}],
            }
        ],
    )

    net = resp["SecondaryNetwork"]
    net_id = net["SecondaryNetworkId"]
    ctx.on_cleanup(lambda: ec2.delete_secondary_network(SecondaryNetworkId=net_id))

    assert net["Type"] == "rdma", f"expected Type 'rdma', got {net['Type']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_secondary_networks(SecondaryNetworkIds=[net_id])[
            "SecondaryNetworks"
        ][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final_state == "create-complete", f"secondary network ended in {final_state!r}"

    # Error boundary: CIDR block size must be between /12 and /28; /30 is too small.
    bad_cidr = "100.64.1.0/30"
    code, message = _error(lambda: ec2.create_secondary_network(Ipv4CidrBlock=bad_cidr, NetworkType="rdma"))
    assert code == "InvalidSecondaryNetwork.Range", (
        f"expected InvalidSecondaryNetwork.Range, got {code!r}"
    )
    assert message == (
        f"The CIDR block '{bad_cidr}' is invalid. Secondary network CIDR blocks must be between /12 and /28."
    ), f"unexpected Range message: {message!r}"


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
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
