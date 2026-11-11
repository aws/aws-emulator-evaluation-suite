"""get-network-resource-counts-invalid-filter-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-network-resource-counts-invalid-filter-validation"
GROUP = "read-consistency"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNetworkResourceCounts rejects an unsupported ResourceType filter; a supported one succeeds."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    _create_site(ctx, nm, gn_id)

    # Break: "not-a-real-type" is not one of the documented resource types.
    code, message = _expect_client_error(
        lambda: nm.get_network_resource_counts(GlobalNetworkId=gn_id, ResourceType="not-a-real-type")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "ResourceType is invalid"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the documented "site" resource type is accepted and eventually counts >= 1.
    counts = _poll_until(
        lambda: nm.get_network_resource_counts(GlobalNetworkId=gn_id, ResourceType="site")[
            "NetworkResourceCounts"
        ],
        lambda entries: any(e["ResourceType"] == "site" and e["Count"] >= 1 for e in entries),
        timeout_s=60.0,
    )
    site_entry = next(e for e in counts if e["ResourceType"] == "site")
    assert site_entry["Count"] >= 1, f"expected site count >= 1, got {site_entry['Count']!r}"


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


def _expect_client_error(fn):
    """Call fn() and return its (code, message); an unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


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
        Tags=[{"Key": "sim2real-team", "Value": "networking"}],
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


def _create_site(ctx, nm, gn_id):
    site_id = nm.create_site(
        GlobalNetworkId=gn_id,
        Description=ctx.unique_name("sim2real-site-"),
        Tags=[{"Key": "sim2real-team", "Value": "networking"}],
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)))
    _poll_until(
        lambda: nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return site_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
