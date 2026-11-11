"""op-contract-get-associated-enclave-certificate-iam-roles."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-associated-enclave-certificate-iam-roles"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAssociatedEnclaveCertificateIamRoles reflects a real AssociateEnclaveCertificateIamRole
    association (including the S3 bucket/object/KMS key it provisions), and rejects a
    certificate ARN with no association by returning an empty role set."""
    import cryptography  # noqa: F401

    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    iam = ctx.client("iam")

    cert_arn = _import_self_signed_cert(acm, "enclave.sim2real.example.com")
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    role_name = ctx.unique_name("sim2real-enclave-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    def _disassociate() -> None:
        ec2.disassociate_enclave_certificate_iam_role(CertificateArn=cert_arn, RoleArn=role_arn)

    _retry_on_propagation(lambda: ec2.associate_enclave_certificate_iam_role(
        CertificateArn=cert_arn, RoleArn=role_arn
    ))
    ctx.on_cleanup(_disassociate)

    # --- success path: association is reflected with real S3/KMS coordinates ---
    roles = _wait_for_role_set(ec2, cert_arn, role_arn)
    assert len(roles) == 1, roles
    assert roles[0]["AssociatedRoleArn"] == role_arn, (
        f"expected AssociatedRoleArn={role_arn!r}, got {roles[0].get('AssociatedRoleArn')!r}"
    )
    assert roles[0]["CertificateS3BucketName"], "expected a real S3 bucket name, got falsy"
    assert roles[0]["CertificateS3ObjectKey"], "expected a real S3 object key, got falsy"
    assert roles[0]["EncryptionKmsKeyId"], "expected a real KMS key id, got falsy"

    # a certificate ARN with no association returns an empty set, not an error
    other_cert_arn = _import_self_signed_cert(acm, "unassociated.sim2real.example.com")
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=other_cert_arn))
    resp = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=other_cert_arn)
    assert resp.get("AssociatedRoles", []) == [], resp.get("AssociatedRoles")

    # --- error boundary: malformed (non-ARN) certificate identifier ---
    code, message = _error(lambda: ec2.get_associated_enclave_certificate_iam_roles(
        CertificateArn="not-a-real-certificate-arn"
    ))
    assert code == "InvalidCertificateArn.Malformed", (
        f"expected InvalidCertificateArn.Malformed for a malformed cert ARN, got {code!r}"
    )
    assert message == "The request must contain a valid certificate arn", message


def _import_self_signed_cert(acm: Any, common_name: str) -> str:
    """Import a leaf certificate signed by a (locally-generated) CA, with a real
    certificate chain attached.

    A bare self-signed leaf (issuer == subject, no CertificateChain) imports into
    ACM successfully and AssociateEnclaveCertificateIamRole even reports success
    against it, but AWS's Nitro-Enclaves-for-ACM backend provisioning (the S3
    bucket/object + KMS key that GetAssociatedEnclaveCertificateIamRoles reports)
    never completes for it -- it silently never surfaces the association, no
    matter how long you poll. A leaf issued by a CA and imported together with
    its CertificateChain is what the feature actually expects, so build a small
    local CA and chain the leaf to it.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.utcnow()

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"ca.{common_name}")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    return acm.import_certificate(
        Certificate=leaf_cert_pem,
        PrivateKey=leaf_key_pem,
        CertificateChain=ca_cert_pem,
        Tags=[{"Key": "Name", "Value": common_name}],
    )["CertificateArn"]


def _retry_on_propagation(fn: Callable[[], Any], timeout_s: float = 45.0, interval_s: float = 3.0) -> Any:
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            # A freshly-created IAM role can take a few seconds to become resolvable
            # (IAM's eventual consistency), during which AssociateEnclaveCertificateIamRole
            # reports it as InvalidRoleArn.NotFound even though the role genuinely exists.
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue", "AccessDenied", "InvalidRoleArn.NotFound",
            ):
                raise
            time.sleep(interval_s)
    raise last_exc  # type: ignore[misc]


def _wait_for_role_set(
    ec2: Any, cert_arn: str, role_arn: str, timeout_s: float = 850.0, interval_s: float = 10.0
) -> list:
    """GetAssociatedEnclaveCertificateIamRoles can, for a while right after
    AssociateEnclaveCertificateIamRole succeeds, still omit the (optional-when-empty)
    AssociatedRoles key entirely rather than returning it as an empty list -- the
    backing S3 bucket/KMS key provisioning (especially the very first association in
    an account/region, which every isolated test account hits) needs some time before
    the association is reflected, so poll for it.

    On real AWS, the very first AssociateEnclaveCertificateIamRole call in a fresh
    account/region can race with that one-time S3 bucket/KMS key provisioning and
    fail to durably persist the association at all -- the call itself returns
    success, but the association never shows up via Get no matter how long you poll
    the read side alone (observed: still absent after 850s of read-only polling).
    Re-issuing AssociateEnclaveCertificateIamRole is idempotent once the role is
    already associated, so re-affirm the write on each iteration (not just the
    read) to recover from that race instead of only ever retrying the read."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            _retry_on_propagation(lambda: ec2.associate_enclave_certificate_iam_role(
                CertificateArn=cert_arn, RoleArn=role_arn
            ))
        except Exception:
            pass
        resp = _retry_on_propagation(
            lambda: ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)
        )
        roles = resp.get("AssociatedRoles") or []
        if roles:
            return roles
        time.sleep(interval_s)
    raise AssertionError("AssociatedRoles never appeared for the associated certificate")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
