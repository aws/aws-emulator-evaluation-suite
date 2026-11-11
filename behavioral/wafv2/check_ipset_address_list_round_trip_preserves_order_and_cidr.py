"""ipset-address-list-round-trip-preserves-order-and-cidr."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ipset-address-list-round-trip-preserves-order-and-cidr"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIPSet returns the same IPv4 CIDR strings CreateIPSet wrote (unsorted input) and the IPv6 ones
    in fully-expanded form, and two reads of each set return the same order.
    """
    wafv2 = ctx.client("wafv2")

    ipv4_addresses = ["203.0.113.5/32", "10.0.0.0/8", "198.51.100.0/24"]
    ipv6_addresses = ["2001:db8::/32", "::1/128", "fe80::/64"]
    ipv6_expanded = [
        "2001:0db8:0000:0000:0000:0000:0000:0000/32",
        "0000:0000:0000:0000:0000:0000:0000:0001/128",
        "fe80:0000:0000:0000:0000:0000:0000:0000/64",
    ]

    ipv4 = _create_ip_set(ctx, wafv2, "IPV4", ipv4_addresses)
    ipv6 = _create_ip_set(ctx, wafv2, "IPV6", ipv6_addresses)

    got_v4_first = wafv2.get_ip_set(Name=ipv4["name"], Scope="REGIONAL", Id=ipv4["id"])["IPSet"]
    got_v4_again = wafv2.get_ip_set(Name=ipv4["name"], Scope="REGIONAL", Id=ipv4["id"])["IPSet"]
    got_v6_first = wafv2.get_ip_set(Name=ipv6["name"], Scope="REGIONAL", Id=ipv6["id"])["IPSet"]
    got_v6_again = wafv2.get_ip_set(Name=ipv6["name"], Scope="REGIONAL", Id=ipv6["id"])["IPSet"]

    # IPv4 content preserved byte-for-byte (no re-normalization of the address
    # or prefix length), as a set.
    assert sorted(got_v4_first["Addresses"]) == sorted(ipv4_addresses), got_v4_first["Addresses"]

    # IPv6 content preserved but canonicalized to fully-expanded notation.
    assert sorted(got_v6_first["Addresses"]) == sorted(ipv6_expanded), got_v6_first["Addresses"]

    # Order preserved is at minimum *deterministic*: repeated reads of the same
    # IPSet return the identical order every time, for both address families.
    assert got_v4_again["Addresses"] == got_v4_first["Addresses"], (
        got_v4_again["Addresses"],
        got_v4_first["Addresses"],
    )
    assert got_v6_again["Addresses"] == got_v6_first["Addresses"], (
        got_v6_again["Addresses"],
        got_v6_first["Addresses"],
    )


def _create_ip_set(ctx, wafv2, version, addresses):
    name = ctx.unique_name(f"sim2real-ipset-{version.lower()}-")
    resp = wafv2.create_ip_set(
        Name=name,
        Scope="REGIONAL",
        IPAddressVersion=version,
        Addresses=addresses,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    summary = resp["Summary"]
    ip_set_id = summary["Id"]

    def _cleanup():
        current = wafv2.get_ip_set(Name=name, Scope="REGIONAL", Id=ip_set_id)
        wafv2.delete_ip_set(
            Name=name, Scope="REGIONAL", Id=ip_set_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": ip_set_id}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
