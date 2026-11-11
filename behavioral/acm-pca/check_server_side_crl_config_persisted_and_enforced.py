"""server-side-crl-config-persisted-and-enforced."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "server-side-crl-config-persisted-and-enforced"
GROUP = "server-side"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CRL RevocationConfiguration set at CA creation is persisted verbatim and unchanged by
    a RevokeCertificate, and a later UpdateCertificateAuthority change is persisted too."""
    acmpca = ctx.client("acm-pca")
    bucket = _setup_crl_bucket(ctx)

    ca_arn = _create_root_ca_with_crl(ctx, bucket, expiration_days=7)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    _activate_root_ca(ctx, ca_arn)

    crl_cfg = _describe(ctx, ca_arn)["RevocationConfiguration"]["CrlConfiguration"]
    assert crl_cfg["Enabled"] is True, f"CRL not enabled after CA creation: {crl_cfg!r}"
    assert crl_cfg["ExpirationInDays"] == 7, (
        f"expected ExpirationInDays=7 as set at creation, got {crl_cfg['ExpirationInDays']!r}"
    )
    assert crl_cfg["S3BucketName"] == bucket, (
        f"expected S3BucketName={bucket!r} as set at creation, got {crl_cfg['S3BucketName']!r}"
    )

    leaf_csr = _scratch_leaf_csr(ctx)
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=leaf_csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
        Validity={"Value": 30, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    _poll_until(lambda: _try_get_certificate(ctx, ca_arn, cert_arn), lambda v: v is not None, timeout_s=60)
    serial = cert_arn.rsplit("/", 1)[-1]

    # RevokeCertificate succeeds because CRL support was configured before
    # the certificate was issued.
    acmpca.revoke_certificate(
        CertificateAuthorityArn=ca_arn, CertificateSerial=serial, RevocationReason="KEY_COMPROMISE"
    )

    crl_cfg_after_revoke = _describe(ctx, ca_arn)["RevocationConfiguration"]["CrlConfiguration"]
    assert crl_cfg_after_revoke == crl_cfg, "CRL config changed as a side effect of revocation"

    acmpca.update_certificate_authority(
        CertificateAuthorityArn=ca_arn,
        RevocationConfiguration={
            "CrlConfiguration": {
                "Enabled": True,
                "ExpirationInDays": 14,
                "S3BucketName": bucket,
                "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL",
            }
        },
    )
    crl_cfg_updated = _poll_until(
        lambda: _describe(ctx, ca_arn)["RevocationConfiguration"]["CrlConfiguration"],
        lambda c: c.get("ExpirationInDays") == 14,
        timeout_s=60,
    )
    assert crl_cfg_updated["ExpirationInDays"] == 14, (
        f"expected ExpirationInDays=14 after UpdateCertificateAuthority, got {crl_cfg_updated['ExpirationInDays']!r}"
    )
    assert crl_cfg_updated["S3BucketName"] == bucket, (
        f"expected S3BucketName={bucket!r} to persist across update, got {crl_cfg_updated['S3BucketName']!r}"
    )
    assert crl_cfg_updated["Enabled"] is True, f"CRL not enabled after update: {crl_cfg_updated!r}"


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


def _describe(ctx, ca_arn: str) -> dict:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]


def _try_get_certificate(ctx, ca_arn: str, cert_arn: str):
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RequestInProgressException":
            return None
        raise


def _create_root_ca_with_crl(ctx, bucket: str, expiration_days: int) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        RevocationConfiguration={
            "CrlConfiguration": {
                "Enabled": True,
                "ExpirationInDays": expiration_days,
                "S3BucketName": bucket,
                "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL",
            }
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    return resp["CertificateAuthorityArn"]


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    scratch_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, scratch_arn))
    acmpca = ctx.client("acm-pca")
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


def _setup_crl_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-acmpca-crl-")
    kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint of us-east-1; the
        # constraint must be omitted entirely to target that region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realAcmPcaCrlRead",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "sim2realAcmPcaCrlWrite",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    from botocore.exceptions import ClientError

    # The still-live CA can write a fresh CRL between the empty and the delete:
    # retry BucketNotEmpty to a deadline, return only once the bucket is gone.
    deadline = time.monotonic() + 30
    while True:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
