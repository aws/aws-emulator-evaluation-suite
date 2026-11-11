"""update-firewall-domains-replace-replaces-whole-set."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-firewall-domains-replace-replaces-whole-set"
GROUP = 'firewall-domain-list'
SERVICES = ['route53resolver']


def _poll(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_when_possible(fn, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """Retry a delete until it succeeds or the resource is gone; raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if "NotFound" in code or code == "ResourceNotFoundException":
                return
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"teardown {fn.__name__}({kwargs}) never succeeded; last error {last}")


def _norm(domains):
    """Compare domain sets without depending on trailing-dot/case normalization.

    Whether Resolver stores `example.com` or `example.com.` is a separate invariant
    (see the trailing-dot check); this one is about REPLACE set semantics, so it
    deliberately canonicalises both ends rather than pinning the projection form.
    """
    return {d.rstrip(".").lower() for d in domains}


def _all_domains(r53, list_id):
    """Return every domain in the list, following pagination."""
    out = []
    token = None
    while True:
        kwargs = {"FirewallDomainListId": list_id, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53.list_firewall_domains(**kwargs)
        out.extend(page.get("Domains", []))
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallDomains Operation=REPLACE replaces the whole set; ADD merges into it.

    DomainCount must track the set after every operation.
    """
    r53 = ctx.client("route53resolver")

    list_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(
        lambda x=list_id: _delete_when_possible(
            r53.delete_firewall_domain_list, FirewallDomainListId=x
        )
    )

    first = ["a1.sim2real-behav.example.com", "a2.sim2real-behav.example.com",
             "a3.sim2real-behav.example.com"]
    replacement = ["b1.sim2real-behav.example.com", "b2.sim2real-behav.example.com"]
    extra = ["c1.sim2real-behav.example.com"]

    def settled_domains(expected):
        """Wait for the domain set to equal `expected`, returning the raw list."""
        return _poll(
            lambda: _all_domains(r53, list_id),
            lambda d: _norm(d) == _norm(expected),
            timeout_s=90,
            interval_s=3,
            description=f"domain list settles to {sorted(_norm(expected))}",
        )

    added = r53.update_firewall_domains(
        FirewallDomainListId=list_id, Operation="ADD", Domains=first
    )
    assert added["Id"] == list_id, added
    assert added["Status"] in ("COMPLETE", "UPDATING", "COMPLETE_IMPORT_FAILED"), added
    settled_domains(first)

    got = r53.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]
    assert got["DomainCount"] == 3, f"DomainCount must track the set after ADD, got {got}"

    # A disjoint, smaller set: if REPLACE merged like ADD, both the count and the set would show it.
    r53.update_firewall_domains(
        FirewallDomainListId=list_id, Operation="REPLACE", Domains=replacement
    )
    after = settled_domains(replacement)
    assert _norm(after) == _norm(replacement), (
        f"REPLACE must replace the whole set, not merge; list holds {sorted(after)}"
    )
    for stale in first:
        assert stale.lower() not in _norm(after), (
            f"{stale} survived a REPLACE that did not include it; list holds {sorted(after)}"
        )

    got = _poll(
        lambda: r53.get_firewall_domain_list(FirewallDomainListId=list_id)[
            "FirewallDomainList"
        ],
        lambda g: g.get("DomainCount") == 2,
        timeout_s=60,
        interval_s=3,
        description="DomainCount drops to 2 after REPLACE",
    )
    assert got["DomainCount"] == 2, got

    # ADD after a REPLACE still merges, so REPLACE did not leave the list read-only.
    r53.update_firewall_domains(
        FirewallDomainListId=list_id, Operation="ADD", Domains=extra
    )
    final = settled_domains(replacement + extra)
    assert _norm(final) == _norm(replacement + extra), (
        f"ADD after REPLACE must merge, got {sorted(final)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
