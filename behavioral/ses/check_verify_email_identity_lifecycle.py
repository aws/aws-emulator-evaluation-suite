"""verify-email-identity-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "verify-email-identity-lifecycle"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _verification_status(ses, identity):
    entry = ses.get_identity_verification_attributes(
        Identities=[identity]
    ).get("VerificationAttributes", {}).get(identity)
    return entry.get("VerificationStatus") if entry else None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VerifyEmailIdentity begins a verification workflow (Pending until the link is clicked) that
    DeleteIdentity fully clears."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    status = _verification_status(ses, email)
    assert status == "Pending", (
        f"expected an unclicked email identity to report Pending, got {status!r}"
    )

    identities = ses.list_identities(IdentityType="EmailAddress")["Identities"]
    assert email in identities, "verified email identity missing from ListIdentities"

    ses.delete_identity(Identity=email)

    status_after = _verification_status(ses, email)
    assert status_after is None, f"identity still reports verification status after delete: {status_after!r}"

    identities_after = ses.list_identities(IdentityType="EmailAddress")["Identities"]
    assert email not in identities_after, "deleted identity still present in ListIdentities"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
