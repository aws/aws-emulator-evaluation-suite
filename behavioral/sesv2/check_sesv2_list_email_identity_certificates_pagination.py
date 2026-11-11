"""sesv2-list-email-identity-certificates-pagination."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sesv2-list-email-identity-certificates-pagination"
GROUP = 'identity-certificate'
SERVICES = ['sesv2']


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEmailIdentityCertificates with PageSize=1 pages over certificate associations one at
    a time: each page holds one entry, the pages are disjoint, NextToken is present until the
    last page, and the union equals the unpaginated read.
    """
    ses = ctx.client('sesv2')
    acm = ctx.client('acm')

    domain = ctx.unique_name('sim2real-behav-cert-') + '.example.com'
    ses.create_email_identity(EmailIdentity=domain, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: _delete_identity_once_certs_clear(ses, domain))

    # A never-validated ACM certificate is free and gives a real CertificateArn to associate;
    # it never needs to be ISSUED.
    cert_arn = acm.request_certificate(
        DomainName=domain, ValidationMethod='DNS', Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )['CertificateArn']
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    from_addresses = [f"alice@{domain}", f"bob@{domain}"]
    for from_address in from_addresses:
        ses.associate_email_identity_certificate(
            EmailIdentity=domain, FromAddress=from_address, CertificateArn=cert_arn,
        )
        ctx.on_cleanup(
            lambda _addr=from_address: ses.disassociate_email_identity_certificate(
                EmailIdentity=domain, FromAddress=_addr,
            )
        )

    unpaginated = ses.list_email_identity_certificates(EmailIdentity=domain)['Certificates']
    assert {c['FromAddress'] for c in unpaginated} == set(from_addresses), (
        f"unpaginated ListEmailIdentityCertificates returned {unpaginated!r}, expected exactly "
        f"{from_addresses!r} -- this identity was freshly created by this check"
    )

    page1 = ses.list_email_identity_certificates(EmailIdentity=domain, PageSize=1)
    page1_certs = page1.get('Certificates') or []
    assert len(page1_certs) == 1, f"PageSize=1 returned {len(page1_certs)} items on page 1: {page1_certs!r}"
    token = page1.get('NextToken')
    assert token, f"page 1 of 2 carried no NextToken even though a second certificate exists: {page1!r}"

    page2 = ses.list_email_identity_certificates(EmailIdentity=domain, PageSize=1, NextToken=token)
    page2_certs = page2.get('Certificates') or []
    assert len(page2_certs) == 1, f"PageSize=1 page 2 returned {len(page2_certs)} items: {page2_certs!r}"
    assert not page2.get('NextToken'), f"page 2 of 2 still carried a NextToken: {page2['NextToken']!r}"

    page1_addr = page1_certs[0]['FromAddress']
    page2_addr = page2_certs[0]['FromAddress']
    assert page1_addr != page2_addr, (
        f"the two PageSize=1 pages returned the SAME FromAddress twice: {page1_addr!r}"
    )
    assert {page1_addr, page2_addr} == set(from_addresses), (
        f"paginated walk {{{page1_addr!r}, {page2_addr!r}}} does not match the unpaginated "
        f"read {set(from_addresses)!r}"
    )
    for cert in (page1_certs[0], page2_certs[0]):
        assert cert.get('CertificateArn') == cert_arn, (
            f"paginated entry CertificateArn={cert.get('CertificateArn')!r}, expected {cert_arn!r}"
        )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
