"""delete-email-identity-blocked-while-certificate-associated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-email-identity-blocked-while-certificate-associated"
GROUP = "identity-certificate"
SERVICES = ["sesv2"]

# Disassociation marks the association INACTIVE rather than removing it, and the delete guard
# keeps firing on the INACTIVE record for tens of seconds to a few minutes afterwards.
_DELETE_DEADLINE_S = 600.0
_DELETE_INTERVAL_S = 2.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEmailIdentity refuses an identity with an associated certificate (exact message); after
    disassociation the record stays INACTIVE and delete succeeds only eventually.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_DeleteEmailIdentity.html
    """
    ses = ctx.client("sesv2")
    domain = ctx.unique_name("sim2real-behav-delguard-") + ".example.com"
    ses.create_email_identity(
        EmailIdentity=domain, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )

    def _best_effort_delete():
        # The check's last step deletes the identity, so not-found here is the normal case.
        try:
            ses.delete_email_identity(EmailIdentity=domain)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise

    ctx.on_cleanup(_best_effort_delete)
    from_address = f"probe@{domain}"
    fake_cert_arn = (
        f"arn:aws:acm:{ctx.region}:{ctx.account}:certificate/"
        "00000000-0000-0000-0000-000000000000"
    )

    ses.associate_email_identity_certificate(
        EmailIdentity=domain, FromAddress=from_address, CertificateArn=fake_cert_arn
    )
    # Disassociation is idempotent (asserted below); on the success path the identity is
    # already gone, which reads as not-found.
    def _disassociate_unless_gone():
        try:
            ses.disassociate_email_identity_certificate(
                EmailIdentity=domain, FromAddress=from_address
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise

    ctx.on_cleanup(_disassociate_unless_gone)

    def _delete_once():
        try:
            ses.delete_email_identity(EmailIdentity=domain)
            return "DELETED"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get(
                "Message", ""
            )

    blocked = _delete_once()
    assert blocked != "DELETED", (
        "DeleteEmailIdentity succeeded while a certificate was associated with the identity; "
        "real AWS must refuse this"
    )
    code, message = blocked
    assert code == "BadRequestException", (
        f"expected BadRequestException deleting an identity with a certificate associated, got "
        f"{code!r} ({message!r})"
    )
    expected_message = (
        f"Cannot delete <arn:aws:ses:{ctx.region}:{ctx.account}:identity/{domain}> because it "
        "has certificates associated with it. Disassociate all certificates and try again."
    )
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the refused delete did not remove the identity (independent read).
    still_present = ses.get_email_identity(EmailIdentity=domain)
    assert still_present["IdentityType"] == "DOMAIN", (
        f"{domain!r} must still read back as a DOMAIN identity after a REFUSED delete, got "
        f"{still_present.get('IdentityType')!r}"
    )

    ses.disassociate_email_identity_certificate(EmailIdentity=domain, FromAddress=from_address)
    # Disassociation is idempotent: a second call on the already-inactive pair must not raise.
    ses.disassociate_email_identity_certificate(EmailIdentity=domain, FromAddress=from_address)

    certs_after_disassociate = ses.list_email_identity_certificates(EmailIdentity=domain)[
        "Certificates"
    ]
    assert certs_after_disassociate and certs_after_disassociate[0]["Status"] == "INACTIVE", (
        f"expected the disassociated certificate record to remain, marked INACTIVE, got "
        f"{certs_after_disassociate!r}"
    )

    # The guard keeps firing on the INACTIVE record for a while -- poll delete to its eventual
    # success rather than asserting it immediately or never.
    deadline = time.monotonic() + _DELETE_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        last = _delete_once()
        if last == "DELETED":
            break
        time.sleep(_DELETE_INTERVAL_S)
    assert last == "DELETED", (
        f"DeleteEmailIdentity never succeeded within {_DELETE_DEADLINE_S}s of disassociating "
        f"every certificate; last refusal was {last!r}"
    )

    after = None
    try:
        ses.get_email_identity(EmailIdentity=domain)
    except ClientError as exc:
        after = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
    expected_after = ("NotFoundException", f"Email identity <{domain}> does not exist.")
    assert after == expected_after, (
        f"expected {expected_after!r} reading {domain!r} after a successful delete, got "
        f"{after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
