"""describe-certificates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-certificates"
GROUP = 'certificates'
SERVICES = ['rds']

ERR_CERTIFICATE_NOT_FOUND = "CertificateNotFound"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCertificates returns a non-empty CA certificate list, filtering by one listed identifier
    returns exactly that certificate, and an unknown identifier is rejected with CertificateNotFound."""
    rds = ctx.client("rds")
    resp = rds.describe_certificates()
    certs = resp.get("Certificates", [])
    assert certs, "expected at least one RDS CA certificate to be listed"
    assert all("CertificateIdentifier" in c for c in certs), (
        f"expected every certificate to carry a CertificateIdentifier, got {certs!r}"
    )

    real_cert_id = certs[0]["CertificateIdentifier"]
    filtered = rds.describe_certificates(CertificateIdentifier=real_cert_id)
    filtered_certs = filtered.get("Certificates", [])
    assert [c["CertificateIdentifier"] for c in filtered_certs] == [real_cert_id], (
        f"filtering by a real CertificateIdentifier {real_cert_id!r} did not return exactly "
        f"that certificate, got {filtered_certs!r}"
    )

    bogus_cert = ctx.unique_name("sim2real-behav-cert-missing-")
    code, message = _error_code(
        lambda: rds.describe_certificates(CertificateIdentifier=bogus_cert)
    )
    assert code == ERR_CERTIFICATE_NOT_FOUND, f"unexpected error code: {code}"
    assert message == f"Certificate {bogus_cert} not found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
