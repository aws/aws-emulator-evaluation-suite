"""describe-global-networks-filters-by-id."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-global-networks-filters-by-id"
GROUP = "read-consistency"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeGlobalNetworks with a mix of a real and an unknown GlobalNetworkId silently
    drops the unknown one instead of raising -- and querying only the unknown ID returns an
    empty list, not an error."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    bogus_id = "global-network-ffffffffffffffff"

    # Mixed real+unknown IDs: no exception; only the real network comes back.
    mixed = nm.describe_global_networks(GlobalNetworkIds=[gn_id, bogus_id])["GlobalNetworks"]
    assert [g["GlobalNetworkId"] for g in mixed] == [gn_id], f"unexpected mixed result: {mixed}"

    # Querying only the unknown ID: empty list, not an error.
    unknown_only = nm.describe_global_networks(GlobalNetworkIds=[bogus_id])["GlobalNetworks"]
    assert unknown_only == [], f"expected empty list for unknown id, got: {unknown_only}"

    # Positive control: querying only the real ID succeeds and returns exactly that network.
    result = nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]
    assert len(result) == 1
    assert result[0]["GlobalNetworkId"] == gn_id
    assert result[0]["State"] == "AVAILABLE"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _is_gone(fn):
    """True once fn() is refused with ResourceNotFoundException or answers an empty list (polling only)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"
    return result == []


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_global_network(ctx, nm):
    gn_id = nm.create_global_network(
        Description=ctx.unique_name("sim2real-gn-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["GlobalNetwork"]["GlobalNetworkId"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id


def _delete_global_network_and_wait(nm, gn_id):
    _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    _poll_until(
        lambda: _is_gone(lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]),
        lambda gone: gone,
        timeout_s=150.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
