"""audit-report-async-completion-managed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

CHECK = "audit-report-async-completion-managed"
GROUP = "server-side"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCertificateAuthorityAuditReport starts a server-managed job that moves CREATING ->
    SUCCESS with no further client call, and the finished report in S3 lists the certificate the
    CA issued."""
    _require_cryptography()
    acmpca = ctx.client("acm-pca")

    ca_arn = _create_root_ca(ctx)
    _activate_root_ca(ctx, ca_arn)
    leaf = _issue_leaf_certificate(ctx, ca_arn, "sim2real-audit-leaf.example.com")

    bucket = _create_bucket(ctx)
    _apply_pca_bucket_policy(ctx, bucket, ca_arn)

    create_resp = acmpca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn,
        S3BucketName=bucket,
        AuditReportResponseFormat="JSON",
    )
    report_id = create_resp["AuditReportId"]

    final_status = None
    s3_key = None
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        desc = acmpca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=report_id
        )
        final_status = desc["AuditReportStatus"]
        s3_key = desc.get("S3Key")
        if final_status != "CREATING":
            break
        time.sleep(5)
    assert final_status == "SUCCESS", f"audit report ended in status {final_status!r}"
    assert s3_key, "a SUCCESS report did not surface an S3Key"

    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=bucket, Key=s3_key)["Body"].read()
    entries = json.loads(body)
    matching = [e for e in entries if e.get("certificateArn") == leaf["certificate_arn"]]
    assert len(matching) == 1, (
        f"issued certificate {leaf['certificate_arn']} not reflected in the "
        f"audit report entries: {entries!r}"
    )
    assert matching[0]["serial"] == leaf["serial_str"], (
        f"audit report entry serial {matching[0]['serial']!r} does not match the "
        f"issued certificate's serial {leaf['serial_str']!r}"
    )


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc


def _wait_for_ca_status(ctx, ca_arn, expected_statuses, timeout_s=120, interval_s=3):
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
        if last in expected_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached {expected_statuses}, last status={last!r}")


def _poll_get_certificate(ctx, ca_arn, cert_arn, timeout_s=120, interval_s=3):
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate(
                CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
            )["Certificate"]
        except acmpca.exceptions.RequestInProgressException:
            time.sleep(interval_s)
    raise AssertionError(f"certificate {cert_arn} never became available")


def _create_root_ca(ctx, revocation_config=None):
    acmpca = ctx.client("acm-pca")
    kwargs = dict(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-pca-")[:64]},
        },
    )
    if revocation_config:
        kwargs["RevocationConfiguration"] = revocation_config
    kwargs["Tags"] = [{"Key": "sim2real", "Value": "audit-report-async-completion-managed"}]
    arn = acmpca.create_certificate_authority(**kwargs)["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, arn))
    return arn


# Inside the 900 s acm-pca cleanup budget, leaving room for the bucket teardown.
_CA_TEARDOWN_S = 780.0


def _delete_ca(ctx, arn):
    """Disable an ACTIVE CA and delete it with the 7-day restoration period until it reads back
    DELETED, where billing stops; retry the documented in-progress answers every 2 s to the
    deadline and raise on anything else."""
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + _CA_TEARDOWN_S
    status = None
    while True:
        try:
            status = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
                "CertificateAuthority"
            ]["Status"]
            if status == "DELETED":
                return
            if status == "ACTIVE":
                acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
            elif status != "CREATING":
                acmpca.delete_certificate_authority(
                    CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
                )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("InvalidStateException", "ConcurrentModificationException"):
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"CA {arn} not DELETED within {_CA_TEARDOWN_S}s (last status {status!r})")
        time.sleep(2)


def _activate_root_ca(ctx, ca_arn):
    acmpca = ctx.client("acm-pca")
    _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"}, timeout_s=120)

    csr_pem = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            csr_pem = acmpca.get_certificate_authority_csr(
                CertificateAuthorityArn=ca_arn
            )["Csr"]
            break
        except acmpca.exceptions.RequestInProgressException:
            time.sleep(3)
    if csr_pem is None:
        raise AssertionError("CSR never became available for root CA")

    cert_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )
    cert_arn = cert_resp["CertificateArn"]
    cert_pem = _poll_get_certificate(ctx, ca_arn, cert_arn)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"}, timeout_s=120)


def _generate_csr_pem(common_name: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.PEM)


def _serial_to_aws_format(serial_int: int) -> str:
    # AWS Private CA's audit report / RevokeCertificate serial strings are the
    # minimal big-endian byte representation of the (positive) serial value --
    # unlike raw X.509 DER, they do NOT prepend a 0x00 sign-disambiguation byte
    # even when the top byte's high bit is set (confirmed against the documented
    # audit report examples, e.g. a serial rendered as "ff:ee:...:00").
    num_bytes = max(1, (serial_int.bit_length() + 7) // 8)
    raw = serial_int.to_bytes(num_bytes, "big")
    return ":".join(f"{b:02x}" for b in raw)


def _issue_leaf_certificate(ctx, ca_arn, common_name, validity_days=365):
    from cryptography import x509

    acmpca = ctx.client("acm-pca")
    csr_pem = _generate_csr_pem(common_name)
    cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": validity_days, "Type": "DAYS"},
    )["CertificateArn"]
    cert_pem = _poll_get_certificate(ctx, ca_arn, cert_arn)
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return {
        "certificate_arn": cert_arn,
        "certificate_pem": cert_pem,
        "serial_int": cert.serial_number,
        "serial_str": _serial_to_aws_format(cert.serial_number),
    }


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-acmpca-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    # us-east-1 is CreateBucket's own default region; passing a LocationConstraint
    # for it is rejected with InvalidLocationConstraint, so it must be omitted only there.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "audit-report-async-completion-managed"}]},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
