"""server-side-audit-report-async-completion."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "server-side-audit-report-async-completion"
GROUP = "server-side"
SERVICES = ["acm-pca"]

ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCertificateAuthorityAuditReport starts an asynchronous job that reaches SUCCESS with a
    populated S3 report location, and AWS Private CA writes the report object to that bucket."""
    acm_pca = ctx.client("acm-pca")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    ca_arn = _create_root_ca(ctx, acm_pca)
    own_cert_arn = _activate_root_ca(ctx, acm_pca, ca_arn)

    account_id = sts.get_caller_identity()["Account"]
    partition = ca_arn.split(":")[1]
    bucket_name = ctx.unique_name("sim2real-acmpca-audit-")
    create_kwargs: dict[str, Any] = {"Bucket": bucket_name}
    # us-east-1 is CreateBucket's own default region; passing a LocationConstraint
    # for it is rejected with InvalidLocationConstraint, so it must be omitted only there.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "server-side-audit-report-async-completion"}]},
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AcmPcaAuditReportWrite",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:{partition}:s3:::{bucket_name}/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": ca_arn},
                },
            },
            {
                "Sid": "AcmPcaAuditReportRead",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:GetBucketLocation"],
                "Resource": f"arn:{partition}:s3:::{bucket_name}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": ca_arn},
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    report = _create_audit_report_with_retry(acm_pca, ca_arn, bucket_name)
    report_id = report["AuditReportId"]
    assert report_id, f"CreateCertificateAuthorityAuditReport returned no AuditReportId: {report!r}"

    final_status, last_report = _poll_report_terminal(acm_pca, ca_arn, report_id)
    assert final_status == "SUCCESS", f"audit report ended in {final_status}: {last_report}"
    assert last_report["S3BucketName"] == bucket_name, (
        f"expected S3BucketName {bucket_name!r}, got {last_report.get('S3BucketName')!r}"
    )
    s3_key = last_report["S3Key"]
    assert s3_key, "S3Key was not populated on a SUCCESS report"

    # The server-side job must have actually written the object, not just claimed to,
    # and the content must genuinely reflect the certificate this CA issued -- a fixed
    # recording cannot carry this CA's own certificate ARN, which is unique per run.
    obj = s3.get_object(Bucket=bucket_name, Key=s3_key)
    body = json.loads(obj["Body"].read())
    assert isinstance(body, list), f"audit report body was not a JSON array: {body!r}"
    matching = [e for e in body if isinstance(e, dict) and e.get("certificateArn") == own_cert_arn]
    assert len(matching) == 1, (
        f"expected exactly one audit report entry for the CA's own certificate "
        f"{own_cert_arn!r}, found {len(matching)}: {body!r}"
    )


def _create_root_ca(ctx, acm_pca) -> str:
    resp = acm_pca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-root-")},
        },
        IdempotencyToken=ctx.unique_name("idem-")[:36],
        Tags=[{"Key": "sim2real", "Value": "server-side-audit-report-async-completion"}],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_ca(acm_pca, ca_arn))
    return ca_arn


def _disable_and_delete_ca(acm_pca, ca_arn: str) -> None:
    try:
        acm_pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        acm_pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_ca_status(acm_pca, ca_arn: str, target_statuses: set[str], timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(3.0)
    raise AssertionError(f"CA never reached {target_statuses}; last status={last}")


def _activate_root_ca(ctx, acm_pca, ca_arn: str) -> str:
    _wait_for_ca_status(acm_pca, ca_arn, {"PENDING_CERTIFICATE"})
    csr = acm_pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    issued = acm_pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=ROOT_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )
    cert_arn = issued["CertificateArn"]
    cert_pem = _poll_get_certificate(acm_pca, ca_arn, cert_arn)
    acm_pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _wait_for_ca_status(acm_pca, ca_arn, {"ACTIVE"})
    return cert_arn


def _poll_get_certificate(acm_pca, ca_arn: str, cert_arn: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acm_pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(2.0)
    raise AssertionError("certificate issuance never completed")


def _create_audit_report_with_retry(acm_pca, ca_arn: str, bucket_name: str, timeout_s: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return acm_pca.create_certificate_authority_audit_report(
                CertificateAuthorityArn=ca_arn,
                S3BucketName=bucket_name,
                AuditReportResponseFormat="JSON",
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("RequestFailedException", "InvalidPolicyException"):
                raise
            last_err = err
            time.sleep(5.0)
    raise AssertionError(f"audit report creation kept failing (bucket policy propagation?): {last_err}")


def _poll_report_terminal(acm_pca, ca_arn: str, report_id: str, timeout_s: float = 300.0):
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = acm_pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=report_id
        )
        status = last["AuditReportStatus"]
        if status in ("SUCCESS", "FAILED"):
            return status, last
        time.sleep(4.0)
    raise AssertionError(f"audit report never reached a terminal state; last={last}")


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
