"""delete-ca-certificate-with-active-certs-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-ca-certificate-with-active-certs-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCACertificate fails with CertificateStateException while the CA itself is ACTIVE;
    deactivating only the CA (its ACTIVE leaf untouched) lets the delete succeed, after which
    describe and update on the CA id fail with ResourceNotFoundException."""
    ca_pem, ca_key = _generate_self_signed_ca()
    leaf_pem = _generate_signed_leaf(ca_pem, ca_key, "sim2real-iot-ca-leaf")

    iot = ctx.client("iot")

    ca_resp = iot.register_ca_certificate(
        caCertificate=ca_pem,
        certificateMode="SNI_ONLY",
        setAsActive=True,
        allowAutoRegistration=False,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ca_id = ca_resp["certificateId"]
    ctx.on_cleanup(lambda: _safe_delete_ca(iot, ca_id))

    leaf_resp = iot.register_certificate(
        certificatePem=leaf_pem, caCertificatePem=ca_pem, status="ACTIVE"
    )
    leaf_id = leaf_resp["certificateId"]
    ctx.on_cleanup(lambda: _safe_deactivate_delete_cert(iot, leaf_id))

    # the leaf must really be ACTIVE and issued by this CA for the legs below to mean anything
    leaf_desc = iot.describe_certificate(certificateId=leaf_id)
    leaf_status = leaf_desc["certificateDescription"]["status"]
    assert leaf_status == "ACTIVE", f"expected leaf cert ACTIVE, got {leaf_status}"
    leaf_ca_id = leaf_desc["certificateDescription"]["caCertificateId"]
    assert leaf_ca_id == ca_id, f"expected leaf cert signed by {ca_id}, got {leaf_ca_id}"

    err = _error(lambda: iot.delete_ca_certificate(certificateId=ca_id))
    assert err == ("CertificateStateException", f"CA Certificate must be deactivated (not ACTIVE) before deletion. Id: {ca_id}"), err

    still_there = iot.describe_ca_certificate(certificateId=ca_id)
    got_status = still_there["certificateDescription"]["status"]
    assert got_status == "ACTIVE", f"expected CA still ACTIVE after rejected delete, got {got_status}"

    iot.update_ca_certificate(certificateId=ca_id, newStatus="INACTIVE")

    leaf_still_active = iot.describe_certificate(certificateId=leaf_id)
    got_leaf_status = leaf_still_active["certificateDescription"]["status"]
    assert got_leaf_status == "ACTIVE", (
        f"expected leaf cert unaffected by the CA's own status change, got {got_leaf_status}"
    )

    # the INACTIVE status can take a moment to be seen by the delete path
    _retry_on_codes(
        lambda: iot.delete_ca_certificate(certificateId=ca_id),
        codes=("CertificateStateException",),
        timeout_s=30,
    )
    not_found = _error(lambda: iot.describe_ca_certificate(certificateId=ca_id))
    assert not_found == ("ResourceNotFoundException", "Requested CA Certificate does not exist."), not_found

    dead_mutation = _error(
        lambda: iot.update_ca_certificate(certificateId=ca_id, newStatus="ACTIVE")
    )
    assert dead_mutation == ("ResourceNotFoundException", "Requested CA Certificate does not exist."), dead_mutation


def _generate_self_signed_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-iot-test-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key


def _generate_signed_leaf(ca_pem: str, ca_key, common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    ca_cert = x509.load_pem_x509_certificate(ca_pem.encode())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _safe_delete_ca(iot, ca_id):
    try:
        iot.delete_ca_certificate(certificateId=ca_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_deactivate_delete_cert(iot, cert_id):
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_on_codes(fn, codes, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
