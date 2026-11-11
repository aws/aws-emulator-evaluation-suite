"""email-address-identity-not-verified-for-sending-on-create-or-get."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "email-address-identity-not-verified-for-sending-on-create-or-get"
GROUP = "identity-v2"
SERVICES = ["sesv2"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new EMAIL_ADDRESS identity is not verified for sending.

    CreateEmailIdentity and an immediate GetEmailIdentity both report VerifiedForSendingStatus
    false, and GetEmailIdentity reports VerificationStatus PENDING.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html
    """
    ses = ctx.client("sesv2")
    email = ctx.unique_name("sim2real-behav-v2addr-") + "@example.com"
    ctx.on_cleanup(
        _teardown(lambda: ses.delete_email_identity(EmailIdentity=email), "NotFoundException")
    )
    created = ses.create_email_identity(
        EmailIdentity=email, Tags=[{"Key": "sim2real", "Value": "behav-v2addr"}]
    )
    assert created["IdentityType"] == "EMAIL_ADDRESS", (
        f"CreateEmailIdentity IdentityType was {created['IdentityType']!r}"
    )
    assert created["VerifiedForSendingStatus"] is False, (
        f"CreateEmailIdentity must report VerifiedForSendingStatus false for an unverified "
        f"address, got {created['VerifiedForSendingStatus']!r}"
    )

    got = ses.get_email_identity(EmailIdentity=email)
    observed = (got["IdentityType"], got["VerifiedForSendingStatus"], got["VerificationStatus"])
    assert observed == ("EMAIL_ADDRESS", False, "PENDING"), (
        f"an immediate GetEmailIdentity must report (EMAIL_ADDRESS, False, PENDING) as "
        f"(IdentityType, VerifiedForSendingStatus, VerificationStatus), got {observed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
