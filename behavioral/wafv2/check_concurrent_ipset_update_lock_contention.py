"""concurrent-ipset-update-lock-contention."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-ipset-update-lock-contention"
GROUP = "server-side"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing UpdateIPSet calls with one shared LockToken yield exactly one winner, every other racer
    fails with WAFOptimisticLockException and the exact message, and the IPSet holds exactly the
    winner's addresses.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-lockrace-")

    created = wafv2.create_ip_set(
        Name=name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=["0.0.0.0/32"],
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ip_set_id = created["Summary"]["Id"]
    shared_lock_token = created["Summary"]["LockToken"]
    ctx.on_cleanup(
        lambda: wafv2.delete_ip_set(
            Name=name,
            Scope=scope,
            Id=ip_set_id,
            LockToken=wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)["LockToken"],
        )
    )

    racer_count = 5
    racer_addresses = {i: [f"10.0.{i}.0/32"] for i in range(racer_count)}

    def _racer(i: int):
        try:
            resp = wafv2.update_ip_set(
                Name=name,
                Scope=scope,
                Id=ip_set_id,
                Addresses=racer_addresses[i],
                LockToken=shared_lock_token,
            )
            return ("ok", i, resp["NextLockToken"])
        except Exception as err:
            error = getattr(err, "response", {}).get("Error", {})
            return ("error", i, error.get("Code"), error.get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]

    assert len(winners) == 1, f"expected exactly one winner among {racer_count} racers, got {results}"
    assert len(losers) == racer_count - 1, (
        f"expected {racer_count - 1} losers among {racer_count} racers, got {results}"
    )
    for _, _, code, message in losers:
        assert code == "WAFOptimisticLockException", (
            f"expected every loser to fail with WAFOptimisticLockException, got {code!r}"
        )
        assert message == (
            "AWS WAF couldn’t save your changes because someone changed the resource after you "
            "started to edit it. Reapply your changes."
        ), message

    winner_index = winners[0][1]
    final = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
    assert final["IPSet"]["Addresses"] == racer_addresses[winner_index], (
        "the IPSet must end up holding exactly the winning racer's addresses, "
        f"got {final['IPSet']['Addresses']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
