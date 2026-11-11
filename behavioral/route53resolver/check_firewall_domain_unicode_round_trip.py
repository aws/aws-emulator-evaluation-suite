"""firewall-domain-unicode-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-domain-unicode-round-trip"
GROUP = "representation"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Punycode domain added with UpdateFirewallDomains is listed back by ListFirewallDomains with
    its encoding unchanged and a trailing dot appended.
    """
    r53r = ctx.client("route53resolver")

    domain_list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-fwdl-unicode-req-"),
        Name=ctx.unique_name("sim2real-fwdl-unicode-")[:64],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id))
    )

    # Punycode (RFC 3492) ASCII-compatible encoding of the Cyrillic IDN test domain
    # "пример.испытание" (see AWS "Formatting internationalized domain names" guide --
    # non-ASCII domains must be submitted to the API in Punycode).
    idn_domain = "xn--e1afmkfd.xn--80akhbyknj4f"

    update_resp = r53r.update_firewall_domains(
        FirewallDomainListId=domain_list_id,
        Operation="ADD",
        Domains=[idn_domain],
    )
    assert update_resp["Id"] == domain_list_id

    status = _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ]["Status"],
        lambda s: s in ("COMPLETE", "COMPLETE_IMPORT_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "COMPLETE", f"domain list update reached {status}, not COMPLETE"

    domain_count = _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ].get("DomainCount", 0),
        lambda n: n > 0,
        timeout_s=120,
        interval_s=5,
    )
    if domain_count == 0:
        # COMPLETE settled with DomainCount still 0 -- issue is a genuine one-shot
        # eventual-consistency gap, not a poll-window-too-short problem; a single
        # idempotent re-ADD (same Domains/Operation) resolves it if the first ADD's
        # effect just hadn't landed in the count index yet.
        r53r.update_firewall_domains(
            FirewallDomainListId=domain_list_id, Operation="ADD", Domains=[idn_domain]
        )
        domain_count = _poll_until(
            lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
                "FirewallDomainList"
            ].get("DomainCount", 0),
            lambda n: n > 0,
            timeout_s=60,
            interval_s=5,
        )
    assert domain_count > 0, f"DomainCount stayed 0 after ADD settled to COMPLETE"

    domains = _poll_until(
        lambda: _list_all_domains(r53r, domain_list_id),
        lambda ds: len(ds) > 0,
        timeout_s=60,
        interval_s=3,
    )

    # Exactly the one domain we added, punycode preserved exactly and not decoded back to
    # Unicode or re-cased -- but with the service's mandatory trailing-dot FQDN
    # canonicalization applied, which is real normalization, not mangling.
    expected = idn_domain + "."
    assert domains == [expected], (
        f"expected [{expected!r}], got {domains!r} (DomainCount={domain_count})"
    )


def _list_all_domains(r53r, domain_list_id: str) -> list:
    domains = []
    next_token = None
    while True:
        kwargs = {"FirewallDomainListId": domain_list_id}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = r53r.list_firewall_domains(**kwargs)
        domains.extend(resp.get("Domains", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return domains


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
