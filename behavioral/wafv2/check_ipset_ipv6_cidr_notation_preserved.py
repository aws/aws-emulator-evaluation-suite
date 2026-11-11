"""ipset-ipv6-cidr-notation-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ipset-ipv6-cidr-notation-preserved"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIPSet returns IPv6 CIDRs given in varied notations as three fully-expanded lowercase entries,
    and an UpdateIPSet resubmitting that list returns a NextLockToken and the same three entries.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-ipset-v6-")

    addresses = [
        "2001:db8::1/128",  # compressed
        "2001:db8:0:0:0:0:0:2/128",  # expanded (explicit zero groups, no leading-zero padding)
        "fe80::/64",  # compressed with a trailing zero-run collapsed
    ]
    # Canonical (fully-expanded, zero-padded) form of each submitted entry, keyed by
    # the entry's identity (its numeric address+prefix), independent of list order.
    expected_canonical_set = {
        "2001:0db8:0000:0000:0000:0000:0000:0001/128",
        "2001:0db8:0000:0000:0000:0000:0000:0002/128",
        "fe80:0000:0000:0000:0000:0000:0000:0000/64",
    }

    created = wafv2.create_ip_set(
        Name=name, Scope=scope, IPAddressVersion="IPV6", Addresses=addresses,
    )
    ipset_id = created["Summary"]["Id"]
    ctx.on_cleanup(lambda: wafv2.delete_ip_set(
        Name=name, Scope=scope, Id=ipset_id,
        LockToken=wafv2.get_ip_set(Name=name, Scope=scope, Id=ipset_id)["LockToken"],
    ))

    got = wafv2.get_ip_set(Name=name, Scope=scope, Id=ipset_id)
    after_create = got["IPSet"]["Addresses"]
    assert set(after_create) == expected_canonical_set, f"got={after_create!r}"
    assert len(after_create) == 3, "duplicate or dropped entry after normalization"

    # Resubmitting the canonical list GetIPSet returned must round-trip the same set. AWS WAF does
    # not keep the order stable across such an UpdateIPSet, so positional order is not asserted.
    updated = wafv2.update_ip_set(
        Name=name, Scope=scope, Id=ipset_id, Addresses=after_create, LockToken=got["LockToken"],
    )
    assert "NextLockToken" in updated, f"update_ip_set response missing NextLockToken: {updated!r}"

    got2 = wafv2.get_ip_set(Name=name, Scope=scope, Id=ipset_id)
    after_update = got2["IPSet"]["Addresses"]
    assert set(after_update) == expected_canonical_set, f"after_update={after_update!r}"
    assert len(after_update) == 3, "duplicate or dropped entry after update round-trip"
    assert all(a == a.lower() for a in after_update), "hex digits were not lowercased consistently"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

