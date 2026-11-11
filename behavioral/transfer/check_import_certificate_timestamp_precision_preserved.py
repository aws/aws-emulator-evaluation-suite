"""import-certificate-timestamp-precision-preserved."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "import-certificate-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportCertificate's ActiveDate/InactiveDate round-trip through DescribeCertificate exactly,
    including the caller-supplied millisecond component (not floored or rounded)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"], "module") from exc

    transfer = ctx.client("transfer")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-transfer-test")])
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now_naive = now.replace(tzinfo=None)  # cryptography's builder wants naive UTC datetimes
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_naive - dt.timedelta(days=1))
        .not_valid_after(now_naive + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    pem = _pem_encode(cert).decode("ascii")

    # Distinct from the certificate's NotBefore/NotAfter; millisecond values survive a
    # double-precision epoch-seconds wire timestamp.
    active_date = now + dt.timedelta(seconds=1, microseconds=123000)
    inactive_date = now + dt.timedelta(days=365, milliseconds=456)

    resp = transfer.import_certificate(
        Usage="SIGNING",
        Certificate=pem,
        ActiveDate=active_date,
        InactiveDate=inactive_date,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    certificate_id = resp["CertificateId"]
    ctx.on_cleanup(lambda: transfer.delete_certificate(CertificateId=certificate_id))

    described = transfer.describe_certificate(CertificateId=certificate_id)["Certificate"]
    returned_active = described["ActiveDate"]
    returned_inactive = described["InactiveDate"]

    assert returned_active == active_date, (
        f"ActiveDate was not preserved exactly: sent {active_date.isoformat()}, "
        f"got {returned_active.isoformat()}"
    )
    assert returned_inactive == inactive_date, (
        f"InactiveDate was not preserved exactly: sent {inactive_date.isoformat()}, "
        f"got {returned_inactive.isoformat()}"
    )
    assert returned_active.microsecond == active_date.microsecond != 0, (
        f"ActiveDate sub-second component was NOT preserved: sent {active_date.isoformat()}, "
        f"got {returned_active.isoformat()}"
    )
    assert returned_inactive.microsecond == inactive_date.microsecond != 0, (
        f"InactiveDate sub-second component was NOT preserved: sent {inactive_date.isoformat()}, "
        f"got {returned_inactive.isoformat()}"
    )


def _pem_encode(cert) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.PEM)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
