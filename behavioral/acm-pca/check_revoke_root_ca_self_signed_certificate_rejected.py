"""revoke-root-ca-self-signed-certificate-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "revoke-root-ca-self-signed-certificate-rejected"
GROUP = "e2e"
SERVICES = ["acm-pca"]

ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Revoking a root CA's own self-signed certificate fails with InvalidRequestException.
    An audit report shows the root certificate still un-revoked, while an end-entity
    certificate from the same CA revokes successfully as a positive control."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc

    acm_pca = ctx.client("acm-pca")

    # ---- set up an ACTIVE root CA --------------------------------------------
    common_name = ctx.unique_name("sim2real-acmpca-neg-")[:64]
    ca_arn = acm_pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _cleanup_ca(ctx, ca_arn))

    status = _wait_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE", "FAILED"}, timeout_s=300)
    assert status == "PENDING_CERTIFICATE", f"CA ended up {status} while awaiting a certificate"

    csr_pem = acm_pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    root_cert_arn = acm_pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=ROOT_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    root_cert_pem = _wait_for_certificate(ctx, ca_arn, root_cert_arn, timeout_s=120)
    root_serial_hex = _serial_hex(x509.load_pem_x509_certificate(root_cert_pem.encode("utf-8")).serial_number)

    acm_pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=root_cert_pem.encode("utf-8")
    )
    status = _wait_ca_status(ctx, ca_arn, {"ACTIVE", "FAILED"}, timeout_s=120)
    assert status == "ACTIVE", f"CA did not become ACTIVE after import (status={status})"

    # ---- issue an ordinary end-entity certificate (the positive-control target) --
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ee_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-ee-neg.example.com")]))
        .sign(ee_key, hashes.SHA256())
    )
    ee_cert_arn = acm_pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=ee_csr.public_bytes(serialization.Encoding.PEM),
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    ee_cert_pem = _wait_for_certificate(ctx, ca_arn, ee_cert_arn, timeout_s=120)
    ee_serial_hex = _serial_hex(x509.load_pem_x509_certificate(ee_cert_pem.encode("utf-8")).serial_number)

    # ---- revoking the CA's own self-signed root cert must fail ----
    code, message = _error(
        lambda: acm_pca.revoke_certificate(
            CertificateAuthorityArn=ca_arn,
            CertificateSerial=root_serial_hex,
            RevocationReason="UNSPECIFIED",
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Self-signed certificate can not be revoked.", f"unexpected message: {message!r}"

    # ---- positive control: revoking the end-entity certificate still works --
    acm_pca.revoke_certificate(
        CertificateAuthorityArn=ca_arn,
        CertificateSerial=ee_serial_hex,
        RevocationReason="UNSPECIFIED",
    )

    # ---- verify the effect: root cert NOT revoked, end-entity cert IS revoked --
    bucket = _prepare_audit_bucket(ctx, ca_arn)
    audit = acm_pca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn, S3BucketName=bucket, AuditReportResponseFormat="JSON"
    )
    audit_status = _wait_audit_report(ctx, ca_arn, audit["AuditReportId"], timeout_s=180)
    assert audit_status == "SUCCESS", f"audit report ended in status={audit_status}"

    obj = ctx.client("s3").get_object(Bucket=bucket, Key=audit["S3Key"])
    entries = json.loads(obj["Body"].read())

    root_entry = next((e for e in entries if e.get("certificateArn") == root_cert_arn), None)
    assert root_entry is not None, "root certificate not present in audit report"
    assert not root_entry.get("revokedAt"), "rejected revoke of the root cert was applied anyway"

    ee_entry = next((e for e in entries if e.get("certificateArn") == ee_cert_arn), None)
    assert ee_entry is not None, "end-entity certificate not present in audit report"
    assert ee_entry.get("revokedAt"), "positive-control revoke of the end-entity cert did not take effect"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_ca_status(ctx, ca_arn: str, target_statuses: set[str], timeout_s: float) -> str:
    acm_pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
        if status in target_statuses:
            return status
        time.sleep(3)
    return status


def _wait_for_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float) -> str:
    from botocore.exceptions import ClientError

    acm_pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acm_pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)[
                "Certificate"
            ]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(2)
    raise AssertionError(f"certificate {cert_arn} never became retrievable within {timeout_s}s")


def _serial_hex(serial_int: int) -> str:
    hex_str = format(serial_int, "x")
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def _prepare_audit_bucket(ctx, ca_arn: str) -> str:
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-acmpca-audit-neg-").lower().replace("_", "-")

    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_bucket(ctx, bucket))

    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSPCAWrite",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    }
                },
            },
            {
                "Sid": "AWSPCARead",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _wait_audit_report(ctx, ca_arn: str, audit_report_id: str, timeout_s: float) -> str:
    acm_pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = acm_pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=audit_report_id
        )["AuditReportStatus"]
        if status in ("SUCCESS", "FAILED"):
            return status
        time.sleep(5)
    return status


# Inside the 900 s acm-pca cleanup budget, leaving room for the bucket teardown.
_CA_TEARDOWN_S = 780.0


def _cleanup_ca(ctx, ca_arn: str) -> None:
    """Disable an ACTIVE CA and delete it with the 7-day restoration period until it reads back
    DELETED, where billing stops; retry the documented in-progress answers every 2 s to the
    deadline and raise on anything else."""
    from botocore.exceptions import ClientError

    acm_pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _CA_TEARDOWN_S
    status = None
    while True:
        try:
            status = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
                "CertificateAuthority"
            ]["Status"]
            if status == "DELETED":
                return
            if status == "ACTIVE":
                acm_pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            elif status != "CREATING":
                acm_pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("InvalidStateException", "ConcurrentModificationException"):
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"CA {ca_arn} not DELETED within {_CA_TEARDOWN_S}s (last status {status!r})")
        time.sleep(2)


def _cleanup_bucket(ctx, bucket: str) -> None:
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
