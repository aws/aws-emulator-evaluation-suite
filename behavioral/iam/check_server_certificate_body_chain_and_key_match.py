"""server-certificate-body-chain-and-key-match."""

from __future__ import annotations

import datetime
import re

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "server-certificate-body-chain-and-key-match"
GROUP = "server-certificates"
SERVICES = ["iam"]

_PATH = "/sim2real/"


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def _cert(subject_cn: str, key, issuer_cn: str, issuer_key, is_ca: bool) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _teardown(iam, name):
    def run_undo() -> None:
        try:
            iam.delete_server_certificate(ServerCertificateName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    return run_undo


def _assert_metadata(label, meta, name, expected_arn, cert) -> None:
    assert meta["ServerCertificateName"] == name, f"{label} name {meta['ServerCertificateName']!r}"
    assert meta["Path"] == _PATH, f"{label} path {meta['Path']!r}"
    assert meta["Arn"] == expected_arn, f"{label} arn {meta['Arn']!r}, expected {expected_arn!r}"
    assert re.fullmatch(r"ASCA[A-Z0-9]{17}", meta["ServerCertificateId"]), (
        f"{label} ServerCertificateId {meta['ServerCertificateId']!r}"
    )
    assert meta["Expiration"] == cert.not_valid_after_utc, (
        f"{label} Expiration {meta['Expiration']!r}, notAfter {cert.not_valid_after_utc!r}"
    )


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetServerCertificate returns the upload's metadata, body and chain minus trailing whitespace.

    A body whose private key does not match is refused and stores nothing.
    """
    iam = ctx.client("iam")
    partition = _partition(ctx)

    ca_key = _key()
    ca_cert = _cert("sim2real-ca.example.com", ca_key, "sim2real-ca.example.com", ca_key, True)
    chain_pem = _pem(ca_cert)

    # Throwaway keys, generated inside the check and discarded with it.
    leaf_key = _key()
    leaf_cert = _cert(
        "sim2real-leaf.example.com", leaf_key, "sim2real-ca.example.com", ca_key, False
    )
    body_pem = _pem(leaf_cert)

    name = ctx.unique_name("sim2real-behav-srvcert-")
    uploaded = iam.upload_server_certificate(
        ServerCertificateName=name,
        Path=_PATH,
        CertificateBody=body_pem,
        PrivateKey=_key_pem(leaf_key),
        CertificateChain=chain_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ServerCertificateMetadata"]
    ctx.on_cleanup(_teardown(iam, name))

    expected_arn = f"arn:{partition}:iam::{ctx.account}:server-certificate{_PATH}{name}"
    _assert_metadata("UploadServerCertificate", uploaded, name, expected_arn, leaf_cert)
    got = iam.get_server_certificate(ServerCertificateName=name)["ServerCertificate"]
    _assert_metadata(
        "GetServerCertificate", got["ServerCertificateMetadata"], name, expected_arn, leaf_cert
    )
    assert got["CertificateBody"] == body_pem.rstrip(), (
        f"GetServerCertificate body differs from the upload (stripped of trailing whitespace): "
        f"{got['CertificateBody']!r}, expected {body_pem.rstrip()!r}"
    )
    assert got["CertificateChain"] == chain_pem.rstrip(), (
        f"GetServerCertificate chain differs from the upload (stripped of trailing whitespace): "
        f"{got.get('CertificateChain')!r}, expected {chain_pem.rstrip()!r}"
    )

    padded_key = _key()
    padded_cert = _cert(
        "sim2real-padded.example.com", padded_key, "sim2real-ca.example.com", ca_key, False
    )
    padded_body = _pem(padded_cert) + "\n  \n"
    padded_name = ctx.unique_name("sim2real-behav-srvcert-pad-")
    iam.upload_server_certificate(
        ServerCertificateName=padded_name,
        CertificateBody=padded_body,
        PrivateKey=_key_pem(padded_key),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(iam, padded_name))
    padded_got = iam.get_server_certificate(ServerCertificateName=padded_name)["ServerCertificate"]
    assert padded_got["CertificateBody"] == padded_body.rstrip(), (
        f"GetServerCertificate stripped the padded body to {padded_got['CertificateBody']!r}, "
        f"expected {padded_body.rstrip()!r}"
    )

    mismatched_name = ctx.unique_name("sim2real-behav-srvcert-mismatch-")
    other_key = _key()
    ctx.on_cleanup(_teardown(iam, mismatched_name))
    code, message = _error(
        lambda: iam.upload_server_certificate(
            ServerCertificateName=mismatched_name,
            CertificateBody=body_pem,
            PrivateKey=_key_pem(other_key),
        )
    )
    assert (code, message) == (
        "KeyPairMismatch",
        "The private key did not match the public key provided. "
        "Please verify the key material and try again.",
    ), f"UploadServerCertificate with a mismatched private key gave {(code, message)!r}"
    absent = _error(lambda: iam.get_server_certificate(ServerCertificateName=mismatched_name))
    assert absent == (
        "NoSuchEntity",
        f"The Server Certificate with name {mismatched_name} cannot be found.",
    ), f"the refused upload left a readable certificate behind: {absent!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
