"""crl-disable-enable-transition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "crl-disable-enable-transition"
GROUP = "state"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableCrl/EnableCrl flip crl.enabled and GetCrl reflects each transition."""
    ca_key, ca_cert, ca_pem = _generate_ca(ctx.unique_name("sim2real-ra-ca-"))
    crl_der = _build_crl(ca_key, ca_cert)

    ra = ctx.client("rolesanywhere")
    ta = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        enabled=True,
    )["trustAnchor"]
    ta_id = ta["trustAnchorId"]
    ctx.on_cleanup(lambda: _delete_ta_ignore_missing(ra, ta_id))

    crl = ra.import_crl(
        name=ctx.unique_name("sim2real-ra-crl-"),
        crlData=crl_der,
        trustAnchorArn=ta["trustAnchorArn"],
        enabled=True,
    )["crl"]
    crl_id = crl["crlId"]
    ctx.on_cleanup(lambda: _delete_crl_ignore_missing(ra, crl_id))

    assert crl["enabled"] is True, f"expected ImportCrl enabled=True, got {crl['enabled']!r}"
    got = ra.get_crl(crlId=crl_id)["crl"]
    assert got["enabled"] is True, f"expected GetCrl enabled=True after import, got {got['enabled']!r}"

    disabled = ra.disable_crl(crlId=crl_id)["crl"]
    assert disabled["enabled"] is False, (
        f"expected DisableCrl enabled=False, got {disabled['enabled']!r}"
    )
    got = ra.get_crl(crlId=crl_id)["crl"]
    assert got["enabled"] is False, (
        f"expected GetCrl enabled=False after DisableCrl, got {got['enabled']!r}"
    )

    enabled = ra.enable_crl(crlId=crl_id)["crl"]
    assert enabled["enabled"] is True, f"expected EnableCrl enabled=True, got {enabled['enabled']!r}"
    got = ra.get_crl(crlId=crl_id)["crl"]
    assert got["enabled"] is True, (
        f"expected GetCrl enabled=True after EnableCrl, got {got['enabled']!r}"
    )


def _generate_ca(common_name: str):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return key, cert, pem


def _build_crl(ca_key, ca_cert) -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(x509.random_serial_number())
        .revocation_date(now)
        .build()
    )
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_revoked_certificate(revoked)
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _delete_ta_ignore_missing(ra, ta_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ra.delete_trust_anchor(trustAnchorId=ta_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_crl_ignore_missing(ra, crl_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ra.delete_crl(crlId=crl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
