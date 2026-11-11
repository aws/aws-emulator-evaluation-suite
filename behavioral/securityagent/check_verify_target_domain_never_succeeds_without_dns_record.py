"""verify-target-domain-never-succeeds-without-dns-record."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "verify-target-domain-never-succeeds-without-dns-record"
GROUP = "state"
SERVICES = ["securityagent"]

_TERMINAL_NEGATIVE = {"FAILED", "UNREACHABLE"}


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """VerifyTargetDomain for a domain whose DNS TXT record was never published leaves PENDING within
    30 s for FAILED or UNREACHABLE, never VERIFIED and with no verifiedAt, and the reported reason
    names the TXT record or DNS as the cause."""
    sa = ctx.client("securityagent")
    domain_name = f"{ctx.unique_name('sim2real-behav-domain-')}.example.com"
    created = sa.create_target_domain(
        targetDomainName=domain_name,
        verificationMethod="DNS_TXT",
        tags={"purpose": "sim2real-behavioral-check"},
    )
    target_domain_id = created["targetDomainId"]
    ctx.on_cleanup(lambda: sa.delete_target_domain(targetDomainId=target_domain_id))

    sa.verify_target_domain(targetDomainId=target_domain_id)

    deadline = time.monotonic() + 30.0
    domain = sa.batch_get_target_domains(targetDomainIds=[target_domain_id])["targetDomains"][0]
    while domain["verificationStatus"] == "PENDING" and time.monotonic() < deadline:
        time.sleep(1.0)
        domain = sa.batch_get_target_domains(targetDomainIds=[target_domain_id])["targetDomains"][0]

    final_status = domain["verificationStatus"]
    assert final_status != "PENDING", (
        "verification of a domain with no published DNS TXT record never left "
        f"PENDING within 30s -- a target that never attempts verification must not "
        f"pass by silence; last read: {domain!r}"
    )
    assert final_status in _TERMINAL_NEGATIVE, (
        "domain without a published DNS TXT record must settle on a terminal "
        f"negative status (FAILED or UNREACHABLE), got {final_status!r}"
    )
    assert domain.get("verifiedAt") is None, (
        f"an unverified domain must never carry a verifiedAt timestamp, got {domain.get('verifiedAt')!r}"
    )
    reason = domain.get("verificationStatusReason") or ""
    assert "TXT" in reason or "DNS" in reason, (
        "verificationStatusReason must name the DNS TXT record as the cause of "
        f"failure, got {reason!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
