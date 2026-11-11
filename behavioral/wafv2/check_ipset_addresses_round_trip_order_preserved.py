"""ipset-addresses-round-trip-order-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ipset-addresses-round-trip-order-preserved"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIPSet returns exactly the CIDR strings written by CreateIPSet and then by UpdateIPSet, none
    dropped, duplicated or reformatted; order is not asserted, as AWS does not keep the request order.
    """
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-ipset-order-")
    scope = "REGIONAL"

    initial_addresses = ["203.0.113.5/32", "198.51.100.0/24", "192.0.2.128/25"]
    created = wafv2.create_ip_set(
        Name=name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=initial_addresses,
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )
    summary = created["Summary"]
    ip_set_id = summary["Id"]

    def _cleanup():
        try:
            cur = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
            wafv2.delete_ip_set(Name=name, Scope=scope, Id=ip_set_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    got = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
    returned_initial = got["IPSet"]["Addresses"]
    assert set(returned_initial) == set(initial_addresses), (
        f"Create round-trip lost/altered addresses: {returned_initial}"
    )
    # No entry should be reformatted even if the array itself is reordered.
    assert sorted(returned_initial) == sorted(initial_addresses), (
        f"Create round-trip mutated an address string: {returned_initial}"
    )

    updated_addresses = ["203.0.113.9/32", "10.0.0.0/16", "192.0.2.0/28", "172.16.0.0/20"]
    wafv2.update_ip_set(
        Name=name,
        Scope=scope,
        Id=ip_set_id,
        Addresses=updated_addresses,
        LockToken=got["LockToken"],
    )

    got2 = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
    returned_updated = got2["IPSet"]["Addresses"]
    assert set(returned_updated) == set(updated_addresses), (
        f"Update round-trip lost/altered addresses: {returned_updated}"
    )
    assert sorted(returned_updated) == sorted(updated_addresses), (
        f"Update round-trip mutated an address string: {returned_updated}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
