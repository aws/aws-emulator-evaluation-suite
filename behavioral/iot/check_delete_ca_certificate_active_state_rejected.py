"""delete-ca-certificate-active-state-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-ca-certificate-active-state-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCACertificate on an ACTIVE CA certificate is rejected with
    CertificateStateException; deactivating it first (breaking the one condition)
    lets the identical delete call succeed as the positive control."""
    pem = _generate_self_signed_ca_pem(ctx.unique_name("sim2real-ca-"))

    iot = ctx.client("iot")
    reg = iot.register_ca_certificate(
        caCertificate=pem,
        certificateMode="SNI_ONLY",
        setAsActive=True,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cert_id = reg["certificateId"]

    cleaned = {"done": False}

    def _cleanup():
        if cleaned["done"]:
            return
        try:
            iot.update_ca_certificate(certificateId=cert_id, newStatus="INACTIVE")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            iot.delete_ca_certificate(certificateId=cert_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    desc = iot.describe_ca_certificate(certificateId=cert_id)
    status = desc["certificateDescription"]["status"]
    assert status == "ACTIVE", f"expected freshly registered CA to be ACTIVE, got {status}"

    err = _error(lambda: iot.delete_ca_certificate(certificateId=cert_id))
    assert err == ("CertificateStateException", f"CA Certificate must be deactivated (not ACTIVE) before deletion. Id: {cert_id}"), err

    # effect absent: the CA certificate must still be registered and ACTIVE
    desc_after = iot.describe_ca_certificate(certificateId=cert_id)
    status_after = desc_after["certificateDescription"]["status"]
    assert status_after == "ACTIVE", (
        f"rejected delete must not change CA state, expected ACTIVE, got {status_after}"
    )

    # break the one condition (deactivate) and confirm the positive control succeeds
    iot.update_ca_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_ca_certificate(certificateId=cert_id)
    cleaned["done"] = True

    err_after = _error(lambda: iot.describe_ca_certificate(certificateId=cert_id))
    assert err_after == ("ResourceNotFoundException", "Requested CA Certificate does not exist."), err_after

    # a mutation on the dead id also fails, not just the read
    mutate_err = _error(
        lambda: iot.update_ca_certificate(certificateId=cert_id, newStatus="ACTIVE")
    )
    assert mutate_err == ("ResourceNotFoundException", "Requested CA Certificate does not exist."), mutate_err


def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _generate_self_signed_ca_pem(common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
