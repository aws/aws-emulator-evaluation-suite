"""sesv2-associate-email-identity-certificate-missing-from-address-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-associate-email-identity-certificate-missing-from-address-rejected"
GROUP = 'identity-certificate'
SERVICES = ['sesv2']


def _error_code(fn):
    """Return fn()'s error Code; an unexpected success raises so acceptance of refused input is
    not reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code']
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _delete_identity_once_certs_clear(ses, domain, *, timeout_s=60.0, interval_s=3.0):
    """DeleteEmailIdentity rejects a domain that still shows an associated certificate, and
    disassociation is eventually consistent -- a delete issued immediately after disassociating
    can observe stale state and fail. Poll ListEmailIdentityCertificates to empty first."""
    deadline = time.monotonic() + timeout_s
    certs = None
    while time.monotonic() < deadline:
        certs = ses.list_email_identity_certificates(EmailIdentity=domain).get('Certificates', [])
        if not certs:
            ses.delete_email_identity(EmailIdentity=domain)
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate associations for {domain!r} never cleared within {timeout_s}s: {certs!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateEmailIdentityCertificate on a DOMAIN identity requires FromAddress; omitting it
    is rejected with BadRequestException, the association is never created, and the same call
    with FromAddress supplied succeeds against the identical certificate.
    """
    ses = ctx.client('sesv2')
    acm = ctx.client('acm')

    domain = ctx.unique_name('sim2real-behav-nofrom-') + '.example.com'
    ses.create_email_identity(EmailIdentity=domain, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: _delete_identity_once_certs_clear(ses, domain))

    cert_arn = acm.request_certificate(
        DomainName=domain, ValidationMethod='DNS', Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )['CertificateArn']
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    code, message = None, None
    try:
        ses.associate_email_identity_certificate(EmailIdentity=domain, CertificateArn=cert_arn)
    except ClientError as exc:
        code = exc.response['Error']['Code']
        message = exc.response['Error'].get('Message') or ''
    else:
        raise AssertionError('AssociateEmailIdentityCertificate without FromAddress on a domain identity succeeded')
    assert code == 'BadRequestException', f"expected BadRequestException, got {code!r} ({message!r})"
    expected_message = "FromAddress is required when EmailIdentity is a domain."
    assert message == expected_message, (
        f"expected the missing-FromAddress refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rejected call created no association at all.
    certs_after_reject = ses.list_email_identity_certificates(EmailIdentity=domain)['Certificates']
    assert certs_after_reject == [], (
        f"a certificate association exists after the rejected call: {certs_after_reject!r}"
    )

    # Positive control: the identical certificate, with FromAddress supplied, associates fine.
    from_address = f"alice@{domain}"
    ses.associate_email_identity_certificate(EmailIdentity=domain, FromAddress=from_address, CertificateArn=cert_arn)
    ctx.on_cleanup(lambda: ses.disassociate_email_identity_certificate(EmailIdentity=domain, FromAddress=from_address))

    certs_after_control = ses.list_email_identity_certificates(EmailIdentity=domain)['Certificates']
    assert [c['FromAddress'] for c in certs_after_control] == [from_address], (
        f"positive control failed: expected exactly one association for {from_address!r}, got {certs_after_control!r}"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
