"""update-crl-replaces-data."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-crl-replaces-data"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCrl replaces crlData in place; GetCrl returns the new bytes and no
    longer the original ones."""
    ca_key, ca_cert, ca_pem = _generate_ca(ctx.unique_name("sim2real-ra-ca-"))
    crl_der_1 = _build_crl(ca_key, ca_cert, days_ahead=1)
    crl_der_2 = _build_crl(ca_key, ca_cert, days_ahead=2)

    sim2real_tags = [{"key": "sim2real", "value": "update-crl-replaces-data"}]

    ra = ctx.client("rolesanywhere")
    ta = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca_pem}},
        tags=sim2real_tags,
    )["trustAnchor"]
    ta_id = ta["trustAnchorId"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta_id))

    crl = ra.import_crl(
        name=ctx.unique_name("sim2real-ra-crl-"),
        crlData=crl_der_1,
        trustAnchorArn=ta["trustAnchorArn"],
        tags=sim2real_tags,
    )["crl"]
    crl_id = crl["crlId"]
    ctx.on_cleanup(lambda: ra.delete_crl(crlId=crl_id))
    assert bytes(crl["crlData"]) != crl_der_2, (
        f"pre-update crlData already matches the target CRL bytes for {crl_id!r}; "
        "the control CRLs are not distinct"
    )

    ra.update_crl(crlId=crl_id, crlData=crl_der_2)

    got = ra.get_crl(crlId=crl_id)["crl"]
    # AWS re-encodes the stored CRL (e.g. re-serializing the PEM), so compare
    # semantic content rather than exact bytes.
    from cryptography import x509

    got_crl = x509.load_pem_x509_crl(bytes(got["crlData"]))
    want_crl = x509.load_pem_x509_crl(crl_der_2)
    stale_crl = x509.load_pem_x509_crl(crl_der_1)
    assert got_crl.next_update_utc == want_crl.next_update_utc, (
        f"GetCrl next_update_utc {got_crl.next_update_utc!r} does not match the "
        f"updated CRL's next_update_utc {want_crl.next_update_utc!r} for {crl_id!r}"
    )
    assert got_crl.next_update_utc != stale_crl.next_update_utc, (
        f"GetCrl next_update_utc {got_crl.next_update_utc!r} still matches the "
        f"pre-update (stale) CRL's next_update_utc {stale_crl.next_update_utc!r} for {crl_id!r}"
    )
    got_serials = {c.serial_number for c in got_crl}
    want_serials = {c.serial_number for c in want_crl}
    assert got_serials == want_serials, (
        f"GetCrl revoked-certificate serials {got_serials!r} do not match the "
        f"updated CRL's serials {want_serials!r} for {crl_id!r}"
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


def _build_crl(ca_key, ca_cert, days_ahead: int) -> bytes:
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
        .next_update(now + datetime.timedelta(days=days_ahead))
        .add_revoked_certificate(revoked)
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
