"""create-email-identity-rejects-one-verifying-through-v1."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-email-identity-rejects-one-verifying-through-v1"
GROUP = "shared-state-v1-v2"
SERVICES = ["ses", "sesv2"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """Return the rejected call's (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SESv2 CreateEmailIdentity on an address SESv1 VerifyEmailIdentity already started verifying
    is rejected, and the pending identity it reads back through both APIs is untouched.
    """
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    pending = f"{ctx.unique_name('sim2real-behav-sharedid-')}@example.com"
    v1.verify_email_identity(EmailAddress=pending)
    ctx.on_cleanup(_teardown(lambda: v2.delete_email_identity(EmailIdentity=pending), "NotFoundException"))

    err = _error(lambda: v2.create_email_identity(EmailIdentity=pending))
    assert err == ("AlreadyExistsException", f"Email identity {pending} already exist."), (
        f"expected v2 CreateEmailIdentity on an address v1 is already verifying to answer "
        f"AlreadyExistsException naming it, got {err!r}"
    )

    v1_attrs = v1.get_identity_verification_attributes(Identities=[pending])["VerificationAttributes"]
    assert v1_attrs[pending]["VerificationStatus"] == "Pending", (
        f"the rejected v2 create must leave the v1-started verification untouched; "
        f"GetIdentityVerificationAttributes reported {v1_attrs.get(pending)!r}"
    )
    v2_identity = v2.get_email_identity(EmailIdentity=pending)
    assert v2_identity["VerificationStatus"] == "PENDING", (
        f"the rejected v2 create must leave the identity untouched; v2 GetEmailIdentity reported "
        f"VerificationStatus={v2_identity['VerificationStatus']!r}"
    )

    # Positive control: creating a DIFFERENT, never-seen identity through v2 succeeds.
    fresh = f"{ctx.unique_name('sim2real-behav-sharedid-')}@example.com"
    v2.create_email_identity(EmailIdentity=fresh)
    ctx.on_cleanup(_teardown(lambda: v2.delete_email_identity(EmailIdentity=fresh), "NotFoundException"))
    fresh_identity = v2.get_email_identity(EmailIdentity=fresh)
    assert fresh_identity["VerificationStatus"] == "PENDING", (
        f"expected the freshly created identity to read back PENDING, got "
        f"{fresh_identity['VerificationStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
