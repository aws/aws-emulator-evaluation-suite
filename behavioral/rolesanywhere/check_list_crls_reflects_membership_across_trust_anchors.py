"""list-crls-reflects-membership-across-trust-anchors."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-crls-reflects-membership-across-trust-anchors"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCrls (paginated) surfaces every imported CRL exactly once, each
    tagged with the trustAnchorArn it was imported against."""
    ca1_key, ca1_cert, ca1_pem = _generate_ca(ctx.unique_name("sim2real-ra-ca1-"))
    ca2_key, ca2_cert, ca2_pem = _generate_ca(ctx.unique_name("sim2real-ra-ca2-"))
    crl1_der = _build_crl(ca1_key, ca1_cert)
    crl2_der = _build_crl(ca2_key, ca2_cert)

    ra = ctx.client("rolesanywhere")

    ta1 = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta1-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca1_pem}},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["trustAnchor"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta1["trustAnchorId"]))

    ta2 = ra.create_trust_anchor(
        name=ctx.unique_name("sim2real-ra-ta2-"),
        source={"sourceType": "CERTIFICATE_BUNDLE", "sourceData": {"x509CertificateData": ca2_pem}},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["trustAnchor"]
    ctx.on_cleanup(lambda: ra.delete_trust_anchor(trustAnchorId=ta2["trustAnchorId"]))

    crl1 = ra.import_crl(
        name=ctx.unique_name("sim2real-ra-crl1-"),
        crlData=crl1_der,
        trustAnchorArn=ta1["trustAnchorArn"],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["crl"]
    ctx.on_cleanup(lambda: ra.delete_crl(crlId=crl1["crlId"]))

    crl2 = ra.import_crl(
        name=ctx.unique_name("sim2real-ra-crl2-"),
        crlData=crl2_der,
        trustAnchorArn=ta2["trustAnchorArn"],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["crl"]
    ctx.on_cleanup(lambda: ra.delete_crl(crlId=crl2["crlId"]))

    found = {}
    next_token = None
    while True:
        kwargs = {"nextToken": next_token, "pageSize": 5} if next_token else {"pageSize": 5}
        resp = ra.list_crls(**kwargs)
        for entry in resp.get("crls", []):
            found[entry["crlId"]] = found.get(entry["crlId"], 0) + 1
            if entry["crlId"] == crl1["crlId"]:
                assert entry["trustAnchorArn"] == ta1["trustAnchorArn"], (
                    f"crl1 listed under trust anchor {entry['trustAnchorArn']!r}, "
                    f"expected {ta1['trustAnchorArn']!r}"
                )
            if entry["crlId"] == crl2["crlId"]:
                assert entry["trustAnchorArn"] == ta2["trustAnchorArn"], (
                    f"crl2 listed under trust anchor {entry['trustAnchorArn']!r}, "
                    f"expected {ta2['trustAnchorArn']!r}"
                )
        next_token = resp.get("nextToken")
        if not next_token:
            break

    assert found.get(crl1["crlId"]) == 1, (
        f"crl1 ({crl1['crlId']}) appeared {found.get(crl1['crlId'], 0)} times in ListCrls, expected exactly 1"
    )
    assert found.get(crl2["crlId"]) == 1, (
        f"crl2 ({crl2['crlId']}) appeared {found.get(crl2['crlId'], 0)} times in ListCrls, expected exactly 1"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
