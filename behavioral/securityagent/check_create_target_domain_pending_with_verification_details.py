"""create-target-domain-pending-with-verification-details."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-target-domain-pending-with-verification-details"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetDomain with DNS_TXT starts in PENDING and returns a concrete DNS TXT
    challenge (token + record name) the caller would need to publish to verify ownership."""
    sa = ctx.client("securityagent")
    domain_name = f"{ctx.unique_name('sim2real-behav-domain-')}.example.com"

    created = sa.create_target_domain(targetDomainName=domain_name, verificationMethod="DNS_TXT")
    target_domain_id = created["targetDomainId"]
    ctx.on_cleanup(lambda: sa.delete_target_domain(targetDomainId=target_domain_id))

    # Terminal read is independent of the mutating CreateTargetDomain call: confirm the PENDING
    # state and the DNS TXT challenge were actually persisted, not just echoed back.
    fetched = sa.batch_get_target_domains(targetDomainIds=[target_domain_id])["targetDomains"][0]
    assert fetched["verificationStatus"] == "PENDING", (
        f"expected PENDING on independent read, got {fetched['verificationStatus']!r}"
    )
    assert fetched["domainName"] == domain_name, (
        f"expected domainName {domain_name!r} on independent read, got {fetched['domainName']!r}"
    )

    dns_txt = fetched["verificationDetails"]["dnsTxt"]
    assert dns_txt["dnsRecordType"] == "TXT", f"expected TXT record type, got {dns_txt['dnsRecordType']!r}"
    assert dns_txt["token"], "expected a non-empty DNS TXT challenge token on independent read"
    assert dns_txt["dnsRecordName"], "expected a non-empty DNS TXT record name on independent read"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
