"""firewall-domain-case-normalization-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-domain-case-normalization-preserved"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallDomains stores a mixed-case domain lowercased, so ListFirewallDomains returns
    the lowercase form whatever spelling was submitted.
    """
    r53r = ctx.client("route53resolver")

    list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-cfdl-"),
        Name=ctx.unique_name("sim2real-fwdomains-")[:64],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_domain_list(r53r, list_id))

    mixed_case_domain = "ExAmple-MiXeDcAsE.TEST."
    normalized_domain = mixed_case_domain.lower()
    r53r.update_firewall_domains(FirewallDomainListId=list_id, Operation="ADD", Domains=[mixed_case_domain])

    # UpdateFirewallDomains is async (FirewallDomainList.Status goes UPDATING ->
    # COMPLETE) -- an immediate ListFirewallDomains can race the write, so wait for
    # the list to settle before treating its projection as authoritative.
    status = _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]["Status"],
        lambda s: s in ("COMPLETE", "COMPLETE_IMPORT_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert status == "COMPLETE", f"domain list update reached {status!r}, not COMPLETE"

    domains = r53r.list_firewall_domains(FirewallDomainListId=list_id)["Domains"]
    assert domains == [normalized_domain], (
        f"expected the mixed-case domain {mixed_case_domain!r} to be normalized to "
        f"{normalized_domain!r} on storage, got {domains!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _safe_delete_domain_list(r53r, list_id):
    try:
        r53r.delete_firewall_domain_list(FirewallDomainListId=list_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
