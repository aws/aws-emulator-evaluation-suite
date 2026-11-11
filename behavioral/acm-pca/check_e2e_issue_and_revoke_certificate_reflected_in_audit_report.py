"""e2e-issue-and-revoke-certificate-reflected-in-audit-report."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-issue-and-revoke-certificate-reflected-in-audit-report"
GROUP = "e2e"
SERVICES = ["acm-pca"]

_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A revoked leaf appears in a later JSON audit report with revokedAt and revocationReason
    UNSPECIFIED, while the never-revoked root certificate's row has no revokedAt."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acmpca = ctx.client("acm-pca")

    ca_arn, root_cert_arn = _create_active_root_ca(ctx)

    leaf_common_name = ctx.unique_name("sim2real-leaf-")
    leaf_cert_arn, leaf_cert_pem = _issue_leaf_certificate(ctx, ca_arn, leaf_common_name)
    leaf_serial = _serial_from_pem(leaf_cert_pem)

    acmpca.revoke_certificate(
        CertificateAuthorityArn=ca_arn,
        CertificateSerial=leaf_serial,
        RevocationReason="UNSPECIFIED",
    )

    bucket = _create_audit_bucket(ctx, ca_arn)
    s3_key = _create_audit_report_and_wait(ctx, ca_arn, bucket)
    rows = _download_json_report(ctx, bucket, s3_key)

    leaf_rows = [r for r in rows if str(r.get("serial", "")).lower() == leaf_serial.lower()]
    assert len(leaf_rows) == 1, (
        f"expected exactly one audit report row for revoked leaf serial {leaf_serial}, "
        f"found {len(leaf_rows)} in {rows}"
    )
    leaf_row = leaf_rows[0]
    assert leaf_row.get("certificateArn") == leaf_cert_arn, leaf_row
    assert leaf_row.get("revokedAt"), (
        f"revoked leaf certificate is missing a populated revokedAt in the audit report: {leaf_row}"
    )
    assert leaf_row.get("revocationReason") == "UNSPECIFIED", leaf_row

    root_rows = [r for r in rows if r.get("certificateArn") == root_cert_arn]
    assert len(root_rows) == 1, f"expected exactly one audit report row for the root cert, got {root_rows}"
    assert not root_rows[0].get("revokedAt"), (
        f"self-signed root certificate (never revoked) unexpectedly shows revokedAt: {root_rows[0]}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _wait_for_csr(ctx, ca_arn: str, timeout_s: float = 60, interval_s: float = 3) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"CA CSR never became available: {last_err}")


def _wait_for_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 90, interval_s: float = 3) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"certificate {cert_arn} never became available: {last_err}")


def _delete_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")

    def _status() -> str:
        return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]

    try:
        status = _status()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _poll_until(_status, lambda s: s == "DISABLED", timeout_s=60, interval_s=3)
    deadline = time.monotonic() + 60
    while True:
        try:
            acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidStateException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _create_active_root_ca(ctx) -> tuple[str, str]:
    """Create a root CA, self-sign its CSR, import the certificate, and wait for ACTIVE."""
    acmpca = ctx.client("acm-pca")
    common_name = ctx.unique_name("sim2real-acmpca-")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": common_name}],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, ca_arn))

    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"],
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=90,
        interval_s=3,
    )

    csr_pem = _wait_for_csr(ctx, ca_arn)
    root_issue = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Value": 3650, "Type": "DAYS"},
    )
    root_cert_arn = root_issue["CertificateArn"]
    root_cert_pem = _wait_for_certificate(ctx, ca_arn, root_cert_arn)

    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=root_cert_pem.encode("utf-8")
    )
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    return ca_arn, root_cert_arn


def _generate_leaf_csr(common_name: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "leaf.key")
        csr_path = os.path.join(d, "leaf.csr")
        subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-subj", f"/CN={common_name}", "-out", csr_path,
            ],
            check=True,
            capture_output=True,
        )
        with open(csr_path, "rb") as f:
            return f.read()


def _issue_leaf_certificate(ctx, ca_arn: str, common_name: str) -> tuple[str, str]:
    acmpca = ctx.client("acm-pca")
    csr_bytes = _generate_leaf_csr(common_name)
    resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_bytes,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 365, "Type": "DAYS"},
    )
    cert_arn = resp["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, ca_arn, cert_arn)
    return cert_arn, cert_pem


def _serial_from_pem(cert_pem: str) -> str:
    """Format matches the colon-separated hex AWS docs say to read via `openssl x509 -text`."""
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(cert_pem)
        out = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-serial"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    finally:
        os.unlink(path)
    hexstr = out.split("=", 1)[1].strip()
    if len(hexstr) % 2:
        hexstr = "0" + hexstr
    return ":".join(hexstr[i : i + 2] for i in range(0, len(hexstr), 2)).lower()


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_audit_bucket(ctx, ca_arn: str) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-acmpca-audit-").lower()

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})

    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AcmPcaGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": ca_arn},
                },
            },
            {
                "Sid": "AcmPcaPutObject",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    },
                    "ArnLike": {"aws:SourceArn": ca_arn},
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _create_audit_report_and_wait(ctx, ca_arn: str, bucket: str, timeout_s: float = 240, interval_s: float = 5) -> str:
    acmpca = ctx.client("acm-pca")

    # Bucket policy attachment can lag briefly behind PutBucketPolicy returning; retry
    # CreateCertificateAuthorityAuditReport on RequestFailedException within a bound.
    deadline = time.monotonic() + 60
    resp = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = acmpca.create_certificate_authority_audit_report(
                CertificateAuthorityArn=ca_arn, S3BucketName=bucket, AuditReportResponseFormat="JSON"
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestFailedException":
                raise
            last_err = err
            time.sleep(interval_s)
    if resp is None:
        raise AssertionError(f"could not create audit report (bucket policy propagation?): {last_err}")

    report_id = resp["AuditReportId"]
    s3_key = resp["S3Key"]

    status = _poll_until(
        lambda: acmpca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=report_id
        )["AuditReportStatus"],
        lambda s: s in ("SUCCESS", "FAILED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    assert status == "SUCCESS", f"audit report generation ended in status {status!r}"
    return s3_key


def _download_json_report(ctx, bucket: str, key: str) -> list:
    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return json.loads(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
