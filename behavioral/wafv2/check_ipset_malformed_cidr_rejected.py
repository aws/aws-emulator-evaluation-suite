"""ipset-malformed-cidr-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ipset-malformed-cidr-rejected"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIPSet rejects an IPv6 CIDR in an IPV4 set with WAFInvalidParameterException and the exact
    IP_ADDRESS message and stores no IPSet; a create with an IPv4 CIDR succeeds and round-trips.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-ipset-bad-")

    code, message = _error(lambda: wafv2.create_ip_set(
        Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=["2001:db8::1/128"],
    ))
    assert code == "WAFInvalidParameterException", (
        f"expected WAFInvalidParameterException for an IPv6 CIDR in an IPV4 set, got {code!r}")
    assert message == (
        "Error reason: The parameter contains formatting that is not valid., "
        "field: IP_ADDRESS, parameter: 2001:db8::1/128"
    ), message

    listing = wafv2.list_ip_sets(Scope=scope)["IPSets"]
    assert all(s["Name"] != name for s in listing), (
        f"rejected create must leave no IPSet named {name!r}, but found one in {listing!r}")

    # Positive control: the same name with a consistent IPv4 CIDR must succeed.
    created = wafv2.create_ip_set(
        Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=["192.0.2.0/24"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ipset_id = created["Summary"]["Id"]
    ctx.on_cleanup(lambda: wafv2.delete_ip_set(
        Name=name, Scope=scope, Id=ipset_id,
        LockToken=wafv2.get_ip_set(Name=name, Scope=scope, Id=ipset_id)["LockToken"],
    ))

    got = wafv2.get_ip_set(Name=name, Scope=scope, Id=ipset_id)
    assert got["IPSet"]["Addresses"] == ["192.0.2.0/24"], (
        f"positive control must round-trip its consistent IPv4 CIDR, got {got['IPSet']['Addresses']!r}")


def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises, so
    an emulator accepting what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
