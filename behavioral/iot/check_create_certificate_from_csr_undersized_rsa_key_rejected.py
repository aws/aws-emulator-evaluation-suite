"""create-certificate-from-csr-undersized-rsa-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "create-certificate-from-csr-undersized-rsa-key-rejected"
GROUP = "certificate-lifecycle"
SERVICES = ["iot"]

_REFUSAL = ("InvalidRequestException", "CSR violates constraints")


def _rsa_csr_pem(key_size: int, common_name: str) -> str:
    """A PEM certificate signing request signed by a fresh RSA key of ``key_size`` bits."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    request = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return request.public_bytes(serialization.Encoding.PEM).decode()


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


def _refused_with(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCertificateFromCsr refuses a CSR whose RSA key is under the documented 2048-bit
    floor; the same request shape at 2048 bits succeeds and is issued.
    """
    iot = ctx.client("iot")

    # positive control: this account and this CSR shape can mint a certificate at all,
    # so the refusal below cannot be mistaken for every CreateCertificateFromCsr call failing
    good_csr = _rsa_csr_pem(2048, ctx.unique_name("sim2real-iot-csr-good-") + ".example.com")
    good = iot.create_certificate_from_csr(certificateSigningRequest=good_csr)
    good_id = good["certificateId"]
    ctx.on_cleanup(_retire_certificate(iot, good_id))
    assert good["certificateId"], "expected a certificateId for the 2048-bit RSA CSR"

    weak_csr = _rsa_csr_pem(1024, ctx.unique_name("sim2real-iot-csr-weak-") + ".example.com")
    refusal = _refused_with(lambda: iot.create_certificate_from_csr(certificateSigningRequest=weak_csr))
    assert refusal == _REFUSAL, f"expected {_REFUSAL!r} for a 1024-bit RSA CSR, got {refusal!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
