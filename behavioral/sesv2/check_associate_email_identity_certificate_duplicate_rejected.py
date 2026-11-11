"""associate-email-identity-certificate-duplicate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-email-identity-certificate-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Associating the same certificate to an identity a second time raises AlreadyExistsException."""
    ses = ctx.client("sesv2")
    acm = ctx.client("acm")

    identity = ctx.unique_name("sim2real-dupcert-") + "@example.com"
    ses.create_email_identity(
        EmailIdentity=identity, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_identity(ses, identity))

    # A throwaway, never-validated ACM certificate is free to request and is enough to have a
    # real CertificateArn to associate -- we never need it ISSUED for this check.
    domain = ctx.unique_name("sim2real-dupcert-") + ".example.com"
    try:
        cert_arn = acm.request_certificate(
            DomainName=domain,
            ValidationMethod="DNS",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["CertificateArn"]
    except ClientError as exc:
        raise AssertionError(f"could not request a throwaway ACM certificate: {exc}")
    # Cleanups run LIFO and independently. The identity holds the certificate, so its delete is
    # registered last and runs first; a failure there never skips the certificate delete.
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    ctx.on_cleanup(lambda: _delete_identity(ses, identity))

    try:
        ses.associate_email_identity_certificate(
            EmailIdentity=identity, CertificateArn=cert_arn
        )
    except ClientError as exc:
        raise AssertionError(
            "SES rejected the first (real, but non-ISSUED) certificate association: "
            f"{exc}; cannot exercise the duplicate-association path without an ISSUED "
            "certificate, which requires owning real DNS for domain validation"
        )

    err = _error(
        lambda: ses.associate_email_identity_certificate(
            EmailIdentity=identity, CertificateArn=cert_arn
        )
    )
    expected = (
        "AlreadyExistsException",
        f"A certificate is already associated with sender <{identity}> on identity <{identity}>.",
    )
    assert err == expected, f"expected {expected}, got {err}"

    # Effect absent: the duplicate call did not create a second entry.
    certs = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
    assert len(certs) == 1, f"expected exactly 1 associated certificate, got {len(certs)}"

    # Positive control: after disassociating, re-associating the very same certificate
    # succeeds again -- proving AlreadyExistsException was about the duplicate STATE, not a
    # permanent block on the identity or the certificate. Disassociation is eventually
    # consistent, so poll until the certificate list actually drains before retrying.
    ses.disassociate_email_identity_certificate(EmailIdentity=identity)

    def _certs_drained():
        return ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]

    _poll_until(_certs_drained, lambda c: c == [], timeout_s=30.0, interval_s=2.0)

    def _reassociate():
        try:
            ses.associate_email_identity_certificate(
                EmailIdentity=identity, CertificateArn=cert_arn
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AlreadyExistsException":
                return False
            raise AssertionError(f"expected re-association to succeed, got {exc}") from exc
        return True

    _poll_until(_reassociate, lambda ok: ok, timeout_s=30.0, interval_s=2.0)
    certs_after = ses.list_email_identity_certificates(EmailIdentity=identity)["Certificates"]
    assert len(certs_after) == 1, f"expected exactly 1 associated certificate after re-associating, got {len(certs_after)}"


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last value: {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


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
