"""associate-email-identity-certificate-unknown-identity-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-email-identity-certificate-unknown-identity-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateEmailIdentityCertificate against an identity that was never created raises
    NotFoundException, while the identical call shape against a real identity, with a real
    (even non-issued) ACM certificate, succeeds and is visible via ListEmailIdentityCertificates."""
    ses = ctx.client("sesv2")
    acm = ctx.client("acm")

    existing_identity = ctx.unique_name("sim2real-assoc-") + "@example.com"
    ses.create_email_identity(
        EmailIdentity=existing_identity, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_identity(ses, existing_identity))

    missing_identity = ctx.unique_name("sim2real-missing-") + "@example.com"
    fake_cert_arn = (
        f"arn:aws:acm:{ctx.region}:111122223333:certificate/"
        "00000000-0000-0000-0000-000000000000"
    )

    expected = ("NotFoundException", f"Email identity <{missing_identity}> does not exist.")
    err = _error(
        lambda: ses.associate_email_identity_certificate(
            EmailIdentity=missing_identity, CertificateArn=fake_cert_arn
        )
    )
    assert err == expected, f"expected {expected}, got {err}"

    # Effect absent: the never-created identity has no certificate list to speak of either.
    list_err = _error(
        lambda: ses.list_email_identity_certificates(EmailIdentity=missing_identity)
    )
    assert list_err == expected, f"expected {expected}, got {list_err}"

    # Positive control: the SAME call shape against a real identity, with a real (even
    # non-issued) ACM certificate ARN, succeeds -- proving NotFoundException was about the
    # identity not existing, not a blanket rejection of AssociateEmailIdentityCertificate.
    # A throwaway, never-validated ACM certificate is free to request and gives a real
    # CertificateArn to associate -- it never needs to be ISSUED for this check.
    domain = ctx.unique_name("sim2real-assoc-") + ".example.com"
    cert_arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")[
        "CertificateArn"
    ]
    # The identity holds the certificate, so it goes first.
    ctx.on_cleanup(
        lambda: (_delete_identity(ses, existing_identity), acm.delete_certificate(CertificateArn=cert_arn))
    )

    try:
        ses.associate_email_identity_certificate(
            EmailIdentity=existing_identity, CertificateArn=cert_arn
        )
    except ClientError as exc:
        raise AssertionError(
            "SES rejected association of a real (non-ISSUED) certificate with a real "
            f"identity: {exc}"
        )

    resp = ses.list_email_identity_certificates(EmailIdentity=existing_identity)
    arns = [c["CertificateArn"] for c in resp["Certificates"]]
    assert arns == [cert_arn], f"expected associated cert [{cert_arn}], got {arns}"


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _delete_identity(ses, identity: str) -> None:
    """Teardown: disassociate any certificate, then delete the identity once SES lets go of it."""
    import time

    deadline = time.monotonic() + 60
    while True:
        try:
            ses.disassociate_email_identity_certificate(EmailIdentity=identity)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NotFoundException":
                raise
        try:
            ses.delete_email_identity(EmailIdentity=identity)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
