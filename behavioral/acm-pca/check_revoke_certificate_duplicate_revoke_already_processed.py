"""revoke-certificate-duplicate-revoke-already-processed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

CHECK = "revoke-certificate-duplicate-revoke-already-processed"
GROUP = "server-side"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Revoking a root CA's own self-signed certificate fails with InvalidRequestException.
    A leaf certificate from the same CA (no CRL/OCSP configured) revokes cleanly, and
    revoking it a second time is rejected as already processed."""
    _require_cryptography()
    acmpca = ctx.client("acm-pca")

    ca_arn = _create_root_ca(ctx)  # no RevocationConfiguration at all
    root_serial = _activate_root_ca(ctx, ca_arn)
    leaf = _issue_leaf_certificate(ctx, ca_arn, "sim2real-norevoke-leaf.example.com")

    # The root CA's own self-signed certificate can never be revoked.
    root_code, root_message = _error(
        lambda: acmpca.revoke_certificate(
            CertificateAuthorityArn=ca_arn,
            CertificateSerial=root_serial,
            RevocationReason="UNSPECIFIED",
        )
    )
    assert root_code == "InvalidRequestException", (
        f"unexpected error code revoking the root CA's self-signed cert: {root_code!r}"
    )
    assert root_message == "Self-signed certificate can not be revoked.", (
        f"unexpected message revoking the root CA's self-signed cert: {root_message!r}"
    )

    # An ordinary leaf certificate revokes cleanly even with no CRL/OCSP
    # configured on the CA at all -- revocation just isn't published anywhere.
    acmpca.revoke_certificate(
        CertificateAuthorityArn=ca_arn,
        CertificateSerial=leaf["serial_str"],
        RevocationReason="UNSPECIFIED",
    )

    # Revoking the same certificate again must now be rejected as already
    # processed -- proving the first call really did take effect.
    second_code, second_message = _error(
        lambda: acmpca.revoke_certificate(
            CertificateAuthorityArn=ca_arn,
            CertificateSerial=leaf["serial_str"],
            RevocationReason="UNSPECIFIED",
        )
    )
    assert second_code == "RequestAlreadyProcessedException", (
        f"unexpected error code on duplicate revoke: {second_code!r}"
    )
    # AWS returns this refusal with an empty message.
    assert second_message == "", f"expected an empty message on duplicate revoke, got {second_message!r}"

    # Independent read at the destination: an audit report confirms the *effect*
    # of both rejections, not just the error codes the mutating calls returned.
    # The root cert must show as never revoked; the leaf must show as revoked
    # exactly once, with the reason from the first (successful) call only --
    # proving the rejected duplicate really had no effect rather than silently
    # overwriting the recorded reason.
    bucket = _create_bucket(ctx)
    _apply_pca_bucket_policy(ctx, bucket, ca_arn)
    audit = acmpca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn, S3BucketName=bucket, AuditReportResponseFormat="JSON"
    )
    audit_status = _wait_for_audit_report(ctx, ca_arn, audit["AuditReportId"])
    assert audit_status == "SUCCESS", f"audit report ended in status={audit_status!r}"

    report = ctx.client("s3").get_object(Bucket=bucket, Key=audit["S3Key"])["Body"].read()
    entries = json.loads(report)

    root_entry = next(
        (e for e in entries if str(e.get("serial", "")).lower() == root_serial.lower()), None
    )
    assert root_entry is not None, f"root cert serial {root_serial} missing from audit report"
    assert not root_entry.get("revokedAt"), (
        f"root CA's self-signed cert shows revoked despite the rejected RevokeCertificate call: {root_entry}"
    )

    leaf_entry = next(
        (e for e in entries if str(e.get("serial", "")).lower() == leaf["serial_str"].lower()), None
    )
    assert leaf_entry is not None, f"leaf cert serial {leaf['serial_str']} missing from audit report"
    assert leaf_entry.get("revokedAt"), f"leaf cert not reflected as revoked: {leaf_entry}"
    assert leaf_entry.get("revocationReason") == "UNSPECIFIED", (
        f"rejected duplicate revoke must not have altered the recorded reason: {leaf_entry}"
    )


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    kwargs["Tags"] = [{"Key": "sim2real", "Value": "true"}]
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

    from cryptography import x509

    root_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return _serial_to_aws_format(root_cert.serial_number)


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
    # AWS Private CA's serial strings are the minimal big-endian byte
    # representation of the (positive) serial value -- they do NOT prepend a
    # 0x00 sign-disambiguation byte even when the top byte's high bit is set.
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


def _wait_for_audit_report(ctx, ca_arn, audit_report_id, timeout_s=180, interval_s=5):
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = acmpca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=audit_report_id
        )["AuditReportStatus"]
        if status in ("SUCCESS", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"audit report {audit_report_id} did not finish within {timeout_s}s, last status={status!r}"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-acmpca-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
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
    s3.put_bucket_ownership_controls(
        Bucket=bucket_name,
        OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]},
    )
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
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    },
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
