"""list-firewall-domains-pagination-no-duplicates."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-firewall-domains-pagination-no-duplicates"
GROUP = 'firewall-domain-list'
SERVICES = ['route53resolver']

DOMAIN_COUNT = 30
PAGE_SIZE = 10


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
    """Canonicalise for set comparison; trailing-dot form is a separate invariant."""
    return {d.rstrip(".").lower() for d in domains}


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListFirewallDomains honours MaxResults, fills every non-final page, yields every
    domain exactly once and then stops; a page holding the whole set carries no NextToken.
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

    suffix = ctx.unique_name("sim2real-behav-")
    expected = [f"p{i:02d}.{suffix}.example.com" for i in range(DOMAIN_COUNT)]
    r53.update_firewall_domains(
        FirewallDomainListId=list_id, Operation="ADD", Domains=expected
    )

    def unpaged():
        """One big page: MaxResults above the item count must return everything."""
        page = r53.list_firewall_domains(
            FirewallDomainListId=list_id, MaxResults=DOMAIN_COUNT * 4
        )
        return page

    settled = _poll(
        unpaged,
        lambda p: _norm(p.get("Domains", [])) == _norm(expected),
        timeout_s=120,
        interval_s=3,
        description=f"all {DOMAIN_COUNT} domains become visible",
    )
    # CONTROL: a page large enough for the whole set must NOT advertise a next page.
    assert settled.get("NextToken") is None, (
        "a page that already returned every domain must not advertise a NextToken, got "
        f"{settled.get('NextToken')!r}"
    )

    pages = []
    token = None
    for _ in range(DOMAIN_COUNT + 5):  # hard loop bound: an endless-token bug must fail
        kwargs = {"FirewallDomainListId": list_id, "MaxResults": PAGE_SIZE}
        if token is not None:
            kwargs["NextToken"] = token
        page = r53.list_firewall_domains(**kwargs)
        domains = page.get("Domains", [])
        assert len(domains) <= PAGE_SIZE, (
            f"MaxResults={PAGE_SIZE} must cap the page; page {len(pages) + 1} returned "
            f"{len(domains)} domains"
        )
        pages.append(domains)
        token = page.get("NextToken")
        if token is None:
            break
        assert isinstance(token, str) and token, f"NextToken must be a non-empty string, got {token!r}"
    else:
        raise AssertionError(
            f"ListFirewallDomains never stopped paginating: {len(pages)} pages for "
            f"{DOMAIN_COUNT} domains"
        )

    assert token is None, f"pagination must terminate with no NextToken, got {token!r}"
    assert len(pages) >= 3, (
        f"{DOMAIN_COUNT} domains at MaxResults={PAGE_SIZE} must span at least 3 pages, "
        f"got {len(pages)} pages of sizes {[len(p) for p in pages]}"
    )

    flat = [d for page in pages for d in page]
    assert len(flat) == DOMAIN_COUNT, (
        f"pagination must yield exactly {DOMAIN_COUNT} domains in total, got {len(flat)} "
        f"across page sizes {[len(p) for p in pages]}"
    )
    seen = _norm(flat)
    assert len(seen) == DOMAIN_COUNT, (
        f"pagination repeated domains: {len(flat)} returned but only {len(seen)} distinct"
    )
    assert seen == _norm(expected), (
        f"pagination lost or invented domains; missing "
        f"{sorted(_norm(expected) - seen)}, unexpected {sorted(seen - _norm(expected))}"
    )

    # Every page before the last must be full; the totals above would hide a short page.
    for i, page in enumerate(pages[:-1]):
        assert len(page) == PAGE_SIZE, (
            f"non-final page {i + 1} returned {len(page)} of MaxResults={PAGE_SIZE}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
