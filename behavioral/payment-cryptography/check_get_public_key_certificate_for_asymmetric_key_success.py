"""get-public-key-certificate-for-asymmetric-key-success."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-public-key-certificate-for-asymmetric-key-success"
GROUP = "data-plane"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPublicKeyCertificate returns a leaf certificate issued by the self-signed CA in
    KeyCertificateChain, whose CN is the account id and whose key size matches RSA_2048; two keys share
    the CA but embed different public keys."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.x509.oid import NameOID

    pc = ctx.client("payment-cryptography")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn_a = _create_signing_key(ctx, pc)
    arn_b = _create_signing_key(ctx, pc)

    cert_a, chain_a = _cert_and_chain(pc, arn_a)
    cert_b, chain_b = _cert_and_chain(pc, arn_b)

    ca_a, ca_b = chain_a[0], chain_b[0]

    for arn, cert, ca_cert in ((arn_a, cert_a, ca_a), (arn_b, cert_b, ca_b)):
        assert cert.issuer == ca_cert.subject, (
            f"leaf certificate issuer for {arn} does not match the CA certificate returned "
            f"in KeyCertificateChain: leaf issuer={cert.issuer.rfc4514_string()!r} "
            f"chain[0] subject={ca_cert.subject.rfc4514_string()!r}"
        )
        assert ca_cert.issuer == ca_cert.subject, (
            f"expected the chain's root CA certificate to be self-signed (issuer == "
            f"subject) for {arn}, got issuer={ca_cert.issuer.rfc4514_string()!r} "
            f"subject={ca_cert.subject.rfc4514_string()!r}"
        )
        # Cryptographic proof, not just name matching: the CA verifies its own
        # signature, and the leaf's signature verifies against the CA's public key.
        ca_cert.public_key().verify(
            ca_cert.signature,
            ca_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ca_cert.signature_hash_algorithm,
        )
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == account_id, (
            f"leaf certificate CN for {arn} is {cn!r}, expected this call's own account "
            f"id {account_id!r}"
        )
        reported_algorithm = pc.get_key(KeyIdentifier=arn)["Key"]["KeyAttributes"]["KeyAlgorithm"]
        assert reported_algorithm == "RSA_2048", (
            f"expected the key's own reported KeyAlgorithm to still be RSA_2048 for {arn}, "
            f"got {reported_algorithm!r}"
        )
        assert cert.public_key().key_size == 2048, (
            f"certificate for {arn} embeds a {cert.public_key().key_size}-bit RSA key, "
            f"expected 2048 to match the key's own reported KeyAlgorithm {reported_algorithm!r}"
        )

    assert ca_a.public_key().public_numbers().n == ca_b.public_key().public_numbers().n, (
        "two independently created keys in the same account were issued by CAs with "
        "different embedded RSA moduli -- expected the same per-account issuing CA"
    )

    modulus_a = cert_a.public_key().public_numbers().n
    modulus_b = cert_b.public_key().public_numbers().n
    assert modulus_a != modulus_b, (
        "two independently created keys produced certificates embedding the identical "
        "RSA modulus -- the certificate is not derived from the key it claims to represent"
    )


def _create_signing_key(ctx, pc):
    key_attributes = {
        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
        "KeyClass": "ASYMMETRIC_KEY_PAIR",
        "KeyAlgorithm": "RSA_2048",
        "KeyModesOfUse": {"Sign": True},
    }
    key = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Key"]
    arn = key["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))
    return arn


def _cert_and_chain(pc, arn: str):
    from cryptography import x509

    resp = pc.get_public_key_certificate(KeyIdentifier=arn)
    cert_pem = _decode_pem(resp["KeyCertificate"])
    chain_pem = _decode_pem(resp["KeyCertificateChain"])
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    chain = x509.load_pem_x509_certificates(chain_pem.encode("ascii"))
    return cert, chain


def _decode_pem(value: str) -> str:
    """The API returns the certificate as PEM text; some accounts/regions instead hand
    back the PEM wrapped in an outer base64 envelope -- decode transparently either way."""
    import base64

    if "-----BEGIN" in value:
        return value
    try:
        return base64.b64decode(value).decode("utf-8", errors="ignore")
    except Exception:
        return value


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
