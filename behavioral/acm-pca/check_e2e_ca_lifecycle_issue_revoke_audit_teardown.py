"""e2e-ca-lifecycle-issue-revoke-audit-teardown."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-ca-lifecycle-issue-revoke-audit-teardown"
GROUP = "e2e"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CA with OCSP issues a leaf, revokes it, and its audit report shows the
    revocation; disabling and deleting the CA then moves it to DELETED."""
    acmpca = ctx.client("acm-pca")

    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    _activate_root_ca(ctx, ca_arn)
    assert _status(ctx, ca_arn) == "ACTIVE"

    leaf_csr = _scratch_leaf_csr(ctx)
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=leaf_csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
        Validity={"Value": 90, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    cert_pem = _poll_until(
        lambda: _try_get_certificate(ctx, ca_arn, cert_arn), lambda v: v is not None, timeout_s=60
    )
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    serial = cert_arn.rsplit("/", 1)[-1]

    acmpca.revoke_certificate(
        CertificateAuthorityArn=ca_arn, CertificateSerial=serial, RevocationReason="KEY_COMPROMISE"
    )

    bucket = _setup_audit_bucket(ctx)
    audit_resp = acmpca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn, S3BucketName=bucket, AuditReportResponseFormat="JSON"
    )
    audit_report_id = audit_resp["AuditReportId"]
    s3_key = audit_resp["S3Key"]

    report_status = _poll_until(
        lambda: acmpca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=audit_report_id
        )["AuditReportStatus"],
        lambda s: s in ("SUCCESS", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert report_status == "SUCCESS", report_status

    s3 = ctx.client("s3")
    report_body = s3.get_object(Bucket=bucket, Key=s3_key)["Body"].read()
    report = json.loads(report_body)
    entries = [e for e in report if e.get("certificateArn") == cert_arn]
    assert len(entries) == 1, f"expected exactly one audit report entry for {cert_arn}, found {len(entries)}"
    assert entries[0]["revocationReason"] == "KEY_COMPROMISE"
    assert "revokedAt" in entries[0]

    # Delete requires the CA to be DISABLED first; deleting directly from
    # ACTIVE raises InvalidStateException on real AWS.
    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    final_status = _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DELETED", timeout_s=60)
    assert final_status == "DELETED"

    # AWS Private CA soft-deletes: the CA stays visible in ListCertificateAuthorities
    # (Status=DELETED) throughout the restoration window rather than vanishing --
    # an independent read at a different operation than Describe/Delete.
    listed = _find_in_list(ctx, ca_arn)
    assert listed is not None, "CA vanished from ListCertificateAuthorities during its restoration window"
    assert listed["Status"] == "DELETED"

    # A DELETED CA must also be unusable: it can no longer issue certificates.
    from botocore.exceptions import ClientError

    try:
        acmpca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=leaf_csr,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
            Validity={"Value": 90, "Type": "DAYS"},
        )
        raise AssertionError("issuing a certificate from a DELETED CA unexpectedly succeeded")
    except ClientError as err:
        refusal = (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
        assert refusal == ("InvalidStateException", "The certificate authority is not in a valid state for issuing certificates"), (
            f"expected InvalidStateException with AWS's exact message issuing a certificate "
            f"against a DELETED CA, got {refusal!r}"
        )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _status(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _try_get_certificate(ctx, ca_arn: str, cert_arn: str):
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RequestInProgressException":
            return None
        raise


def _find_in_list(ctx, ca_arn: str):
    acmpca = ctx.client("acm-pca")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = acmpca.list_certificate_authorities(**kwargs)
        for ca in resp.get("CertificateAuthorities", []):
            if ca["Arn"] == ca_arn:
                return ca
        token = resp.get("NextToken")
        if not token:
            return None


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        # OCSP revocation must be configured before the certificate we will
        # revoke is issued -- no S3 bucket is required for OCSP.
        RevocationConfiguration={"OcspConfiguration": {"Enabled": True}},
    )
    return resp["CertificateAuthorityArn"]


def _activate_root_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    def _get_csr():
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    csr = _poll_until(_get_csr, lambda v: v is not None, timeout_s=60)
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 3650, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    cert_pem = _poll_until(lambda: _try_get_certificate(ctx, ca_arn, cert_arn), lambda v: v is not None, timeout_s=60)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "ACTIVE", timeout_s=60)


def _scratch_leaf_csr(ctx) -> bytes:
    """Obtain a syntactically valid PKCS#10 CSR (backed by a fresh keypair)
    by spinning up a throwaway CA purely to harvest its CSR -- avoids
    depending on 'cryptography'/openssl to generate a CSR client-side."""
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-scratch-")[:64]},
        },
    )
    scratch_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, scratch_arn))
    from botocore.exceptions import ClientError

    def _get_csr():
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=scratch_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    csr = _poll_until(_get_csr, lambda v: v is not None, timeout_s=60)
    return csr.encode("utf-8")


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        status = _status(ctx, ca_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    if status != "DELETED":
        acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)


def _setup_audit_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-acmpca-audit-")
    kwargs: dict = {"Bucket": bucket}
    # S3's own CreateBucket contract, not a pin to ctx.region: LocationConstraint must be
    # omitted specifically for us-east-1 and set to the target region everywhere else.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realAcmPcaAuditAccess",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetBucketAcl", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    from botocore.exceptions import ClientError

    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
