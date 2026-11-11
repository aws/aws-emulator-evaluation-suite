"""update-firewall-domains-add-remove-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-firewall-domains-add-remove-lifecycle"
GROUP = 'firewall-domain-list'
SERVICES = ['route53resolver']

def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallDomains ADD/REMOVE actually mutates DomainCount and domain contents."""
    r53 = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-fdl-")
    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    domains = ["example.com", "test.example.com"]
    added = r53.update_firewall_domains(
        FirewallDomainListId=dl_id, Operation="ADD", Domains=domains
    )
    assert added["Id"] == dl_id, added
    assert added["Status"] in ("COMPLETE", "UPDATING"), added

    def domain_count():
        return r53.get_firewall_domain_list(FirewallDomainListId=dl_id)[
            "FirewallDomainList"
        ]["DomainCount"]

    _poll(
        domain_count,
        lambda c: c == 2,
        timeout_s=60,
        interval_s=2,
        description="DomainCount reaches 2 after ADD",
    )

    def listed_domains():
        # Domains may be returned with a trailing dot; compare normalized.
        return {
            d.lower().rstrip(".")
            for d in r53.list_firewall_domains(FirewallDomainListId=dl_id)["Domains"]
        }

    _poll(
        listed_domains,
        lambda s: s == {"example.com", "test.example.com"},
        timeout_s=60,
        interval_s=2,
        description="ListFirewallDomains reflects both added domains",
    )

    removed = r53.update_firewall_domains(
        FirewallDomainListId=dl_id, Operation="REMOVE", Domains=["example.com"]
    )
    assert removed["Id"] == dl_id, removed
    assert removed["Status"] in ("COMPLETE", "UPDATING"), removed
    _poll(
        domain_count,
        lambda c: c == 1,
        timeout_s=60,
        interval_s=2,
        description="DomainCount drops to 1 after REMOVE",
    )
    _poll(
        listed_domains,
        lambda s: s == {"test.example.com"},
        timeout_s=60,
        interval_s=2,
        description="REMOVE deleted only the targeted domain",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
