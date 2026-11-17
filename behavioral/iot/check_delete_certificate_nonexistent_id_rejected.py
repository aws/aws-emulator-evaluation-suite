"""delete-certificate-nonexistent-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-certificate-nonexistent-id-rejected"
GROUP = 'certificate-lifecycle'
SERVICES = ['iot']


def _csr_pem(common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    return csr.public_bytes(Encoding.PEM).decode()


def _delete_certificate(iot, cert_id):
    """Teardown: deactivate then force-delete; a certificate already gone is clean."""
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _err(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificate on a certificate id that was never issued fails ResourceNotFoundException,
    while the same call against a real, deactivated certificate succeeds and removes it.
    """
    iot = ctx.client("iot")

    # Positive control: DeleteCertificate itself works against a certificate this check issued
    # and deactivated, so the rejection below is specific to the missing id.
    csr_pem = _csr_pem(ctx.unique_name("sim2real-iot-csr-"))
    created = iot.create_certificate_from_csr(certificateSigningRequest=csr_pem, setAsActive=False)
    cert_id = created["certificateId"]
    ctx.on_cleanup(lambda: _delete_certificate(iot, cert_id))

    iot.delete_certificate(certificateId=cert_id)
    code, message = _err(lambda: iot.describe_certificate(certificateId=cert_id))
    assert code == "ResourceNotFoundException", (
        f"positive control: expected the deleted certificate to read back not-found, got {code}: {message!r}"
    )
    assert message == f"CertificateId {cert_id} does not exist", (
        f"positive control: unexpected message {message!r}"
    )

    never_issued_id = "ab" * 32
    code, message = _err(
        lambda: iot.delete_certificate(certificateId=never_issued_id, forceDelete=True)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an id never issued, got {code}: {message!r}"
    )
    assert message == f"CertificateId {never_issued_id} does not exist", (
        f"unexpected message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
