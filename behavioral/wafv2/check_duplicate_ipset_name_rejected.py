"""duplicate-ipset-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "duplicate-ipset-name-rejected"
GROUP = "server-side"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIPSet with a Name already used in the Scope fails with WAFDuplicateItemException and the
    exact message, leaving the original IPSet's addresses and listing unchanged, while an unused name
    creates a new IPSet.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-dupe-ipset-")

    original = wafv2.create_ip_set(
        Name=name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=["192.0.2.1/32"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    original_id = original["Summary"]["Id"]
    ctx.on_cleanup(
        lambda: wafv2.delete_ip_set(
            Name=name,
            Scope=scope,
            Id=original_id,
            LockToken=wafv2.get_ip_set(Name=name, Scope=scope, Id=original_id)["LockToken"],
        )
    )

    code, message = _error(
        lambda: wafv2.create_ip_set(
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=["203.0.113.2/32"]
        )
    )
    assert code == "WAFDuplicateItemException", f"expected WAFDuplicateItemException, got {code!r}"
    assert message == (
        "AWS WAF couldn’t perform the operation because some resource in your request is a "
        "duplicate of an existing one."
    ), message

    # The effect of the rejected duplicate create must be absent: the original IPSet's
    # own addresses are untouched, and there is still exactly one IPSet with this name.
    unchanged = wafv2.get_ip_set(Name=name, Scope=scope, Id=original_id)
    assert unchanged["IPSet"]["Addresses"] == ["192.0.2.1/32"], (
        f"expected original IPSet addresses untouched at ['192.0.2.1/32'], "
        f"got {unchanged['IPSet']['Addresses']!r}"
    )
    matching = [s for s in _list_all_ip_sets(wafv2, scope) if s["Name"] == name]
    assert len(matching) == 1 and matching[0]["Id"] == original_id, (
        f"expected exactly one IPSet named {name!r} with Id {original_id!r}, got {matching!r}"
    )

    # Positive control: a genuinely different name still creates successfully.
    other_name = ctx.unique_name("sim2real-behav-dupe-ipset-other-")
    other = wafv2.create_ip_set(
        Name=other_name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=["198.51.100.3/32"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    other_id = other["Summary"]["Id"]
    ctx.on_cleanup(
        lambda: wafv2.delete_ip_set(
            Name=other_name,
            Scope=scope,
            Id=other_id,
            LockToken=wafv2.get_ip_set(Name=other_name, Scope=scope, Id=other_id)["LockToken"],
        )
    )
    other_addrs = wafv2.get_ip_set(Name=other_name, Scope=scope, Id=other_id)["IPSet"]["Addresses"]
    assert other_addrs == ["198.51.100.3/32"], (
        f"expected positive-control IPSet addresses ['198.51.100.3/32'], got {other_addrs!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected real AWS to reject this call, but it SUCCEEDED: {result!r}")


def _list_all_ip_sets(wafv2, scope: str) -> list:
    items = []
    marker = None
    while True:
        kwargs = {"Scope": scope}
        if marker:
            kwargs["NextMarker"] = marker
        page = wafv2.list_ip_sets(**kwargs)
        items.extend(page["IPSets"])
        marker = page.get("NextMarker")
        if not marker:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
