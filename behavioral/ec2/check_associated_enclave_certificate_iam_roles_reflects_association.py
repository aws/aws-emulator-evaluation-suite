"""associated-enclave-certificate-iam-roles-reflects-association."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "associated-enclave-certificate-iam-roles-reflects-association"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After AssociateEnclaveCertificateIamRole, GetAssociatedEnclaveCertificateIamRoles
    lists exactly that role/certificate pair -- no more, no less -- and the pair
    disappears again after DisassociateEnclaveCertificateIamRole."""
    require_tools("openssl")

    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    iam = ctx.client("iam")

    cert_pem, key_pem = _self_signed_cert(ctx)
    cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    role_name = ctx.unique_name("sim2real-enclave-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Before any association, this certificate must show no associated roles.
    before = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)
    assert before.get("AssociatedRoles", []) == [], (
        f"expected no associated roles before any association, got {before.get('AssociatedRoles')}"
    )

    # IAM role creation is eventually consistent -- retry past the window
    # where EC2 hasn't yet observed the new role.
    deadline = time.monotonic() + 60
    while True:
        try:
            assoc = ec2.associate_enclave_certificate_iam_role(
                CertificateArn=cert_arn, RoleArn=role_arn
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleArn.NotFound" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(5)
    ctx.on_cleanup(
        lambda: ec2.disassociate_enclave_certificate_iam_role(
            CertificateArn=cert_arn, RoleArn=role_arn
        )
    )

    after = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)
    roles = after.get("AssociatedRoles", [])
    assert len(roles) == 1, f"expected exactly one associated role, got {roles}"
    assert roles[0]["AssociatedRoleArn"] == role_arn, (
        f"expected associated role {role_arn}, got {roles[0]['AssociatedRoleArn']}"
    )
    assert roles[0]["CertificateS3BucketName"] == assoc["CertificateS3BucketName"], (
        f"S3 bucket mismatch: get returned {roles[0]['CertificateS3BucketName']!r}, "
        f"associate returned {assoc['CertificateS3BucketName']!r}"
    )
    assert roles[0]["CertificateS3ObjectKey"] == assoc["CertificateS3ObjectKey"], (
        f"S3 object key mismatch: get returned {roles[0]['CertificateS3ObjectKey']!r}, "
        f"associate returned {assoc['CertificateS3ObjectKey']!r}"
    )

    ec2.disassociate_enclave_certificate_iam_role(CertificateArn=cert_arn, RoleArn=role_arn)

    final = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)
    assert final.get("AssociatedRoles", []) == [], (
        f"expected no associated roles after disassociation, got {final.get('AssociatedRoles')}"
    )


def _self_signed_cert(ctx) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        cn = ctx.unique_name("sim2real-enclave-")
        cmd = [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "2",
            "-subj",
            f"/CN={cn}.example.com",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
        except subprocess.CalledProcessError as exc:
            raise AssertionError(f"openssl failed to generate a self-signed cert: {exc}")
        return cert_path.read_text(), key_path.read_text()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
