"""associate-email-identity-certificate-email-address-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-email-identity-certificate-email-address-mismatch-rejected"
GROUP = "identity-certificate"
SERVICES = ["acm", "sesv2"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _drain(ses, identity, *, timeout_s=60.0, interval_s=2.0):
    """Disassociation is eventually consistent; poll ListEmailIdentityCertificates to empty
    before relying on the identity carrying no association."""
    deadline = time.monotonic() + timeout_s
    certs = None
    while time.monotonic() < deadline:
        certs = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
        if not certs:
            return
        time.sleep(interval_s)
    raise AssertionError(f"certificates for {identity!r} never drained within {timeout_s}s: {certs!r}")


def _delete_identity_once_clear(ses, identity, *, timeout_s=60.0, interval_s=2.0):
    """DeleteEmailIdentity rejects an identity that still shows an associated certificate;
    poll the delete itself to convergence rather than assuming disassociation already landed."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ses.delete_email_identity(EmailIdentity=identity)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEmailIdentityCertificate on an EMAIL_ADDRESS identity needs no FromAddress:
    omitting it or supplying the identical address both succeed, but a mismatched FromAddress
    is rejected and creates no association, as ListEmailIdentityCertificates shows each time.
    """
    ses = ctx.client("sesv2")
    acm = ctx.client("acm")

    identity = ctx.unique_name("sim2real-behav-emailid-") + "@example.com"
    ses.create_email_identity(EmailIdentity=identity, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_identity_once_clear(ses, identity))

    cert_domain = ctx.unique_name("sim2real-behav-emailid-cert-") + ".example.com"
    cert_arn = acm.request_certificate(
        DomainName=cert_domain, ValidationMethod="DNS", Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    # FromAddress omitted: the identity itself is the only possible mailbox.
    ses.associate_email_identity_certificate(EmailIdentity=identity, CertificateArn=cert_arn)
    certs_omitted = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
    assert [c["FromAddress"] for c in certs_omitted] == [identity], (
        f"expected exactly one association for {identity!r} with FromAddress omitted, got {certs_omitted!r}"
    )
    assert certs_omitted[0]["CertificateArn"] == cert_arn, (
        f"expected CertificateArn {cert_arn!r}, got {certs_omitted[0].get('CertificateArn')!r}"
    )
    ses.disassociate_email_identity_certificate(EmailIdentity=identity)
    _drain(ses, identity)

    # FromAddress supplied but identical to the identity: also succeeds.
    ses.associate_email_identity_certificate(
        EmailIdentity=identity, FromAddress=identity, CertificateArn=cert_arn
    )
    certs_matched = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
    assert [c["FromAddress"] for c in certs_matched] == [identity], (
        f"expected exactly one association for {identity!r} with a matching FromAddress, got {certs_matched!r}"
    )
    ses.disassociate_email_identity_certificate(EmailIdentity=identity)
    _drain(ses, identity)

    # FromAddress that does not match the identity is rejected, and creates no association.
    mismatched = ctx.unique_name("sim2real-behav-notowner-") + "@example.com"
    _MISMATCH_REJECTED = (
        "BadRequestException",
        f"FromAddress <{mismatched}> must match the email identity <{identity}>.",
    )
    expect_error(
        lambda: ses.associate_email_identity_certificate(
            EmailIdentity=identity, FromAddress=mismatched, CertificateArn=cert_arn
        ),
        *_MISMATCH_REJECTED,
    )
    certs_after_reject = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
    assert certs_after_reject == [], (
        f"a certificate association exists after the rejected mismatched-FromAddress call: {certs_after_reject!r}"
    )

    # Positive control: the identical certificate, with FromAddress omitted again, still
    # associates fine after the rejection above.
    ses.associate_email_identity_certificate(EmailIdentity=identity, CertificateArn=cert_arn)
    ctx.on_cleanup(lambda: ses.disassociate_email_identity_certificate(EmailIdentity=identity))
    certs_control = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
    assert [c["FromAddress"] for c in certs_control] == [identity], (
        f"positive control failed: expected exactly one association for {identity!r}, got {certs_control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
