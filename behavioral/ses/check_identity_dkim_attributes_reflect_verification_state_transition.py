"""identity-dkim-attributes-reflect-verification-state-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "identity-dkim-attributes-reflect-verification-state-transition"
GROUP = "state-machine"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VerifyDomainDkim returns 3 tokens and GetIdentityDkimAttributes reports Pending, staying
    Pending because the throwaway domain never publishes the CNAME records Success requires."""
    ses = ctx.client("ses")
    domain = f"{ctx.unique_name('sim2real-ses-dkim-')}.example.com"
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=domain))

    tokens = ses.verify_domain_dkim(Domain=domain)["DkimTokens"]
    assert len(tokens) == 3, f"VerifyDomainDkim expected exactly 3 DKIM tokens, got {len(tokens)}: {tokens!r}"

    attrs = ses.get_identity_dkim_attributes(Identities=[domain])["DkimAttributes"][domain]
    assert attrs["DkimVerificationStatus"] == "Pending", attrs["DkimVerificationStatus"]
    assert set(attrs["DkimTokens"]) == set(tokens), (attrs["DkimTokens"], tokens)

    # Bounded poll confirming the status does not spuriously race to Success
    # in the short term -- it should remain Pending since no DNS records for
    # this made-up domain were ever published.
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        status = ses.get_identity_dkim_attributes(Identities=[domain])["DkimAttributes"][domain][
            "DkimVerificationStatus"
        ]
        assert status == "Pending", status
        time.sleep(4.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
