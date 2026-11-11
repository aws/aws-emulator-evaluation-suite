"""op-contract-disassociate-enclave-certificate-iam-role."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "op-contract-disassociate-enclave-certificate-iam-role"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateEnclaveCertificateIamRole with DryRun answers DryRunOperation and the role stays
    associated with the ACM certificate; the real call returns true and the role no longer appears in
    GetAssociatedEnclaveCertificateIamRoles."""
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    iam = ctx.client("iam")

    cert_arn = _import_self_signed_cert(ctx, acm)

    role_name = ctx.unique_name("sim2real-enclave-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    resp = _poll_until(
        lambda: _try_associate_cert_role(ec2, cert_arn, role_arn),
        lambda v: v is not None,
        timeout_s=420.0,
        interval_s=15.0,
    )
    assert resp["CertificateS3BucketName"], resp
    assert resp["CertificateS3ObjectKey"], resp

    # GetAssociatedEnclaveCertificateIamRoles lists the IAM roles associated with an ACM certificate,
    # in AssociatedRoles / AssociatedRoleArn.
    roles = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)["AssociatedRoles"]
    assert any(r["AssociatedRoleArn"] == role_arn for r in roles), roles

    # Error boundary: DryRun must report DryRunOperation without disassociating.
    code, message = _client_error(
        lambda: ec2.disassociate_enclave_certificate_iam_role(CertificateArn=cert_arn, RoleArn=role_arn, DryRun=True)
    )
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    still = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)["AssociatedRoles"]
    assert any(r["AssociatedRoleArn"] == role_arn for r in still), still

    disassoc = ec2.disassociate_enclave_certificate_iam_role(CertificateArn=cert_arn, RoleArn=role_arn)
    assert disassoc["Return"] is True, disassoc

    after = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)["AssociatedRoles"]
    assert not any(r["AssociatedRoleArn"] == role_arn for r in after), after


def _try_associate_cert_role(ec2, cert_arn, role_arn):
    """Associate the role, answering None while AWS still propagates the new ACM certificate
    (InvalidCertificateArn.Malformed) or the new IAM role (InvalidRoleArn.NotFound), so the caller's
    bounded poll retries; re-raise anything else."""
    from botocore.exceptions import ClientError

    try:
        return ec2.associate_enclave_certificate_iam_role(CertificateArn=cert_arn, RoleArn=role_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidCertificateArn.Malformed", "InvalidRoleArn.NotFound"):
            return None
        raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _import_self_signed_cert(ctx, acm) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "cert.key"
        crt_path = Path(tmp) / "cert.crt"
        cn = ctx.unique_name("sim2real-enclave-cert-")
        require_tools("openssl")
        try:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key_path), "-out", str(crt_path),
                    "-days", "2", "-nodes", "-subj", f"/CN={cn}",
                    # The certificate must be a TLS server certificate: a codeSigning EKU, a keyUsage without
                    # keyEncipherment, or no Subject Alternative Name each fail AssociateEnclaveCertificateIamRole
                    # with InvalidCertificateArn.Malformed.
                    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                    "-addext", "extendedKeyUsage=critical,serverAuth",
                    "-addext", f"subjectAltName=DNS:{cn}",
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            raise AssertionError(f"openssl failed to generate a self-signed cert ({exc})") from None
        cert_arn = acm.import_certificate(
            Certificate=crt_path.read_bytes(),
            PrivateKey=key_path.read_bytes(),
            Tags=[{"Key": "sim2real", "Value": "op-contract-disassociate-enclave-certificate-iam-role"}],
        )["CertificateArn"]
        ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
        return cert_arn


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
