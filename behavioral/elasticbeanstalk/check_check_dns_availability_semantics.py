"""check-dns-availability-semantics."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "check-dns-availability-semantics"
GROUP = 'environment-data-plane'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CheckDNSAvailability reports availability plus the region-qualified CNAME it would take.

    FullyQualifiedCNAME is ``<prefix>.<region>.<service domain>``; the service domain is the
    target's own, so only the prefix and region segments are pinned.
    """
    eb = ctx.client("elasticbeanstalk")
    prefix = ctx.unique_name("sim2real-behav-eb-dns-").lower()[:50]
    resp = eb.check_dns_availability(CNAMEPrefix=prefix)
    assert resp["Available"] is True, "a freshly generated CNAME prefix must be available"
    fqdn = resp["FullyQualifiedCNAME"]
    head = f"{prefix}.{ctx.region}."
    assert fqdn.startswith(head) and len(fqdn) > len(head), (
        f"FullyQualifiedCNAME must be <prefix>.<region>.<service domain>; expected it to start "
        f"with {head!r} and carry a domain, got {fqdn!r}"
    )
    domain = fqdn[len(head):]
    assert "." in domain and prefix not in domain and ctx.region not in domain, (
        f"FullyQualifiedCNAME must carry exactly one prefix and one region segment, got {fqdn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
