"""create-audit-report-not-ready-fails."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-audit-report-not-ready-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call succeeded; expected a ClientError")


def _delete_ca(ctx, ca_arn):
    try:
        ctx.client("acm-pca").update_certificate_authority(
            CertificateAuthorityArn=ca_arn, Status="DISABLED"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_ca(ctx, **overrides):
    """Create a cheap, never-activated ROOT CA (SHORT_LIVED_CERTIFICATE usage mode,
    never issues a cert) and register its teardown. Retries on throttling since
    CreateCertificateAuthority has a low request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
        "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
    }
    body.update(overrides)
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


def _wait_for_ca_status(pca, ca_arn: str, target_statuses: set[str], timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(3.0)
    raise AssertionError(f"CA never reached {target_statuses}; last status={last}")


def _poll_get_certificate(pca, ca_arn: str, cert_arn: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(2.0)
    raise AssertionError("certificate issuance never completed")


def _activate_root_ca(pca, ca_arn: str) -> None:
    """Self-sign the ROOT CA's own CSR and import it, moving the CA to ACTIVE."""
    _wait_for_ca_status(pca, ca_arn, {"PENDING_CERTIFICATE"})
    csr = pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    issued = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=ROOT_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )
    cert_arn = issued["CertificateArn"]
    cert_pem = _poll_get_certificate(pca, ca_arn, cert_arn)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _wait_for_ca_status(pca, ca_arn, {"ACTIVE"})


def _create_report_bucket(ctx, ca_arn: str) -> str:
    """A bucket + policy AWS Private CA is allowed to write an audit report to.
    Created up front so the only difference between the refused call and the
    restored call is the CA's own readiness, not the bucket's."""
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    partition = ca_arn.split(":")[1]
    bucket_name = ctx.unique_name("sim2real-acmpca-audit-")
    create_kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
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
    return bucket_name


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthorityAuditReport on a not-yet-active CA fails with
    InvalidStateException, leaves the CA state unchanged, and succeeds once the CA is activated."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    bucket_name = _create_report_bucket(ctx, arn)

    call = lambda: pca.create_certificate_authority_audit_report(  # noqa: E731
        CertificateAuthorityArn=arn,
        S3BucketName=bucket_name,
        AuditReportResponseFormat="JSON",
    )

    code, message = _err(call)
    assert code == "InvalidStateException", code
    assert message == (
        f"The certificate authority {arn} is not in the correct state to have issued "
        "certificates."
    ), message

    status_after_refusal = pca.describe_certificate_authority(CertificateAuthorityArn=arn)[
        "CertificateAuthority"
    ]["Status"]
    assert status_after_refusal in {"CREATING", "PENDING_CERTIFICATE"}, status_after_refusal

    _activate_root_ca(pca, arn)
    resp = call()
    assert resp.get("AuditReportId"), "CreateCertificateAuthorityAuditReport succeeded but returned no AuditReportId"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
