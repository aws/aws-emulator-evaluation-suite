"""disassociate-email-identity-certificate-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-email-identity-certificate-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateEmailIdentityCertificate on a never-created identity raises NotFoundException with its exact
    message (GetEmailIdentity agrees), while on a real identity without a certificate it is a no-op success
    that leaves no certificates.
    """
    ses = ctx.client("sesv2")

    missing_identity = ctx.unique_name("sim2real-disassoc-missing-") + "@example.com"
    missing_message = f"Email identity <{missing_identity}> does not exist."
    err = _error(
        lambda: ses.disassociate_email_identity_certificate(EmailIdentity=missing_identity)
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err!r}"
    assert err.get("Message") == missing_message, (
        f"expected message {missing_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: an independent read confirms the identity does not exist, so the
    # NotFoundException from disassociate is about the missing identity.
    get_missing = _error(lambda: ses.get_email_identity(EmailIdentity=missing_identity))
    assert get_missing.get("Code") == "NotFoundException", (
        f"expected NotFoundException, got {get_missing!r}"
    )
    assert get_missing.get("Message") == missing_message, (
        f"expected message {missing_message!r}, got {get_missing.get('Message')!r}"
    )

    # Positive control: on a real identity with no associated certificate the call is a no-op,
    # so NotFoundException is about the identity, not about "nothing to disassociate".
    identity = ctx.unique_name("sim2real-disassoc-") + "@example.com"
    ses.create_email_identity(
        EmailIdentity=identity, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=identity))

    # Must NOT raise: disassociating with no certificate present is a no-op on a real identity.
    ses.disassociate_email_identity_certificate(EmailIdentity=identity)

    certs = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
    assert certs == [], f"expected no associated certificates, got {certs}"

    got = ses.get_email_identity(EmailIdentity=identity)
    assert got["IdentityType"] == "EMAIL_ADDRESS", (
        f"expected identity to still exist as EMAIL_ADDRESS, got {got.get('IdentityType')}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
