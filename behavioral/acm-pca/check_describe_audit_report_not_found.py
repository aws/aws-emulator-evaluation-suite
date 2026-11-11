"""describe-audit-report-not-found."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-audit-report-not-found"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

def _err(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

def _poll_audit_report(pca, ca_arn, report_id, *, timeout_s):
    """Poll DescribeCertificateAuthorityAuditReport until the report leaves CREATING.
    RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=report_id
        )["AuditReportStatus"]
        if status != "CREATING":
            return status
        time.sleep(3.0)
    raise AssertionError(f"audit report {report_id} still {status!r} after {timeout_s}s")

def _delete_ca(ctx, ca_arn):
    pca = ctx.client("acm-pca")
    try:
        status = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
    except pca.exceptions.ResourceNotFoundException:
        return
    if status == "DELETED":
        return
    if status == "ACTIVE":
        # DeleteCertificateAuthority refuses an ACTIVE CA: disable it first.
        pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _wait_for_ca_status(ctx, ca_arn, {"DISABLED"}, timeout_s=60)
    pca.delete_certificate_authority(
        CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
    )

def _create_ca(ctx):
    """Create a ROOT CA and register its teardown. Retries on throttling since
    CreateCertificateAuthority has a low request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "Tags": [{"Key": "sim2real", "Value": "describe-audit-report-not-found"}],
    }
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, ca_arn))
    return ca_arn

def _wait_for_ca_status(ctx, ca_arn, expected_statuses, timeout_s=120, interval_s=3):
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
        if last in expected_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached {expected_statuses}, last status={last!r}")

def _poll_get_certificate(ctx, ca_arn, cert_arn, timeout_s=120, interval_s=3):
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return pca.get_certificate(
                CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
            )["Certificate"]
        except pca.exceptions.RequestInProgressException:
            time.sleep(interval_s)
    raise AssertionError(f"certificate {cert_arn} never became available")

def _activate_ca(ctx, ca_arn):
    """Self-sign the root CA's own CSR and import it back, so the CA reaches ACTIVE and can accept
    CreateCertificateAuthorityAuditReport -- an unactivated CA rejects that call with
    InvalidStateException, so activation is the prerequisite for a genuine (positive-control) audit
    report id."""
    pca = ctx.client("acm-pca")
    _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"}, timeout_s=120)

    csr_pem = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            csr_pem = pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
            break
        except pca.exceptions.RequestInProgressException:
            time.sleep(3)
    if csr_pem is None:
        raise AssertionError("CSR never became available for root CA")

    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    cert_pem = _poll_get_certificate(ctx, ca_arn, cert_arn)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"}, timeout_s=120)

def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-pca-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":  # S3 quirk: us-east-1 rejects an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "describe-audit-report-not-found"}]},
    )
    return name

def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise

def _apply_pca_bucket_policy(ctx, bucket_name, ca_arn):
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PCAWrite",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnEquals": {"aws:SourceArn": ca_arn},
                },
            },
            {
                "Sid": "PCARead",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnEquals": {"aws:SourceArn": ca_arn},
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCertificateAuthorityAuditReport refuses an unknown report id with
    ResourceNotFoundException, while a real report id on the same active CA describes
    as SUCCESS, so the refusal is keyed on the report id."""
    pca = ctx.client("acm-pca")
    ca_arn = _create_ca(ctx)
    _activate_ca(ctx, ca_arn)
    bucket = _create_bucket(ctx)
    _apply_pca_bucket_policy(ctx, bucket, ca_arn)

    real_report_id = pca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn,
        S3BucketName=bucket,
        AuditReportResponseFormat="JSON",
    )["AuditReportId"]

    real_status = _poll_audit_report(pca, ca_arn, real_report_id, timeout_s=180.0)
    assert real_status == "SUCCESS", real_status

    refusal = _err(
        lambda: pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn,
            AuditReportId="00000000-0000-0000-0000-000000000000",
        )
    )
    assert refusal == ("ResourceNotFoundException", "Could not find specified Audit Report."), refusal


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
