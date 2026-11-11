"""verify-domain-identity-and-dkim-tokens."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "verify-domain-identity-and-dkim-tokens"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_domain(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


def _verification_status(ses, identity):
    entry = ses.get_identity_verification_attributes(
        Identities=[identity]
    ).get("VerificationAttributes", {}).get(identity)
    return entry.get("VerificationStatus") if entry else None


def _dkim_attributes(ses, identity):
    return ses.get_identity_dkim_attributes(
        Identities=[identity]
    ).get("DkimAttributes", {}).get(identity)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VerifyDomainIdentity/VerifyDomainDkim create a Pending identity and exactly 3 DKIM CNAME tokens."""
    ses = ctx.client("ses")
    domain = _unique_domain(ctx)
    resp = ses.verify_domain_identity(Domain=domain)
    ctx.on_cleanup(lambda _n=domain: ses.delete_identity(Identity=_n))
    assert resp.get("VerificationToken"), "VerifyDomainIdentity did not return a VerificationToken"

    status = _verification_status(ses, domain)
    assert status == "Pending", (
        f"a freshly verified domain with no published DNS records must be Pending, not {status!r} "
        "-- Success here means the target skipped the DNS-detection step VerifyDomainIdentity depends on"
    )

    dkim_resp = ses.verify_domain_dkim(Domain=domain)
    tokens = dkim_resp.get("DkimTokens", [])
    assert len(tokens) == 3, f"expected VerifyDomainDkim to return exactly 3 tokens, got {len(tokens)}"

    dkim_attrs = _dkim_attributes(ses, domain)
    assert dkim_attrs is not None, "GetIdentityDkimAttributes missing entry for verified domain"
    assert dkim_attrs.get("DkimVerificationStatus") == "Pending", (
        f"Easy DKIM with no published CNAME records must be Pending, not "
        f"{dkim_attrs.get('DkimVerificationStatus')!r} -- Success here means the target skipped DNS detection"
    )
    assert dkim_attrs.get("DkimTokens") == tokens, "DkimTokens from attributes differ from VerifyDomainDkim response"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
