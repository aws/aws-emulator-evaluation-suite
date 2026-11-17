"""create-certificate-from-csr-public-key-and-activation-state."""
from __future__ import annotations

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    CertificateSigningRequestBuilder,
    Name,
    NameAttribute,
    load_pem_x509_certificate,
)
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "create-certificate-from-csr-public-key-and-activation-state"
GROUP = "certificate-lifecycle"
SERVICES = ["iot"]


def _rsa_csr(common_name: str):
    """A fresh 2048-bit RSA key and the PEM certificate signing request it signs."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    request = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return key, request.public_bytes(serialization.Encoding.PEM).decode()


def _retire_certificate(iot, certificate_id: str):
    """Teardown: move the certificate to INACTIVE, then delete it; absent is already clean."""

    def undo() -> None:
        try:
            iot.update_certificate(certificateId=certificate_id, newStatus="INACTIVE")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            iot.delete_certificate(certificateId=certificate_id, forceDelete=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    return undo


def _status_by_listing(iot, certificate_id: str) -> str:
    """The ``status`` ListCertificates reports for ``certificate_id``, paginating the whole set."""
    for page in iot.get_paginator("list_certificates").paginate():
        for entry in page["certificates"]:
            if entry["certificateId"] == certificate_id:
                return entry["status"]
    raise AssertionError(f"ListCertificates never returned certificate {certificate_id!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCertificateFromCsr issues a certificate whose public key is the CSR's own key;
    the certificate is INACTIVE unless setAsActive is true, as ListCertificates reports it.
    """
    iot = ctx.client("iot")

    first_key, first_csr = _rsa_csr(ctx.unique_name("sim2real-iot-csr-") + ".example.com")
    first = iot.create_certificate_from_csr(certificateSigningRequest=first_csr)
    first_id = first["certificateId"]
    ctx.on_cleanup(_retire_certificate(iot, first_id))

    expected_arn = f"arn:aws:iot:{ctx.region}:{ctx.account}:cert/{first_id}"
    assert first["certificateArn"] == expected_arn, (
        f"expected certificateArn {expected_arn!r}, got {first['certificateArn']!r}"
    )

    first_issued_numbers = load_pem_x509_certificate(
        first["certificatePem"].encode()
    ).public_key().public_numbers()
    first_csr_numbers = first_key.public_key().public_numbers()
    assert (first_issued_numbers.n, first_issued_numbers.e) == (
        first_csr_numbers.n,
        first_csr_numbers.e,
    ), "the issued certificate's public key does not match the CSR's own key"

    assert _status_by_listing(iot, first_id) == "INACTIVE", (
        "expected the certificate to be INACTIVE when setAsActive is omitted"
    )

    second_key, second_csr = _rsa_csr(ctx.unique_name("sim2real-iot-csr-") + ".example.com")
    second = iot.create_certificate_from_csr(
        certificateSigningRequest=second_csr, setAsActive=True
    )
    second_id = second["certificateId"]
    ctx.on_cleanup(_retire_certificate(iot, second_id))

    second_issued_numbers = load_pem_x509_certificate(
        second["certificatePem"].encode()
    ).public_key().public_numbers()
    second_csr_numbers = second_key.public_key().public_numbers()
    assert (second_issued_numbers.n, second_issued_numbers.e) == (
        second_csr_numbers.n,
        second_csr_numbers.e,
    ), "the issued certificate's public key does not match the second CSR's own key"

    assert _status_by_listing(iot, second_id) == "ACTIVE", (
        "expected the certificate to be ACTIVE when setAsActive=True"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
