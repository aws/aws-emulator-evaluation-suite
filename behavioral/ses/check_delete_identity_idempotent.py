"""delete-identity-idempotent."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "delete-identity-idempotent"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentity is idempotent: deleting a never-verified or already-deleted identity does not raise."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    # Deleting an identity that was never created must not raise.
    ses.delete_identity(Identity=email)

    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    # Setup precondition: verify actually created a pending identity, so the deletes below have
    # something real to remove rather than passing vacuously against a no-op verify/delete pair.
    identities_after_verify = ses.list_identities(IdentityType="EmailAddress")["Identities"]
    assert email in identities_after_verify, (
        f"setup precondition: {email!r} missing after verify_email_identity, "
        f"got {identities_after_verify!r}"
    )

    ses.delete_identity(Identity=email)
    # Deleting the same identity again must still not raise.
    ses.delete_identity(Identity=email)

    identities_after = ses.list_identities(IdentityType="EmailAddress")["Identities"]
    assert email not in identities_after, "identity present after idempotent double-delete"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
