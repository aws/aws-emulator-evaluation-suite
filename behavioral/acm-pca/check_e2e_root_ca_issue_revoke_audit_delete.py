"""e2e-root-ca-issue-revoke-audit-delete."""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "e2e-root-ca-issue-revoke-audit-delete"
GROUP = "e2e"
SERVICES = ["acm-pca"]

ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"

# A poll's bounded wait; never an assertion on time.
_POLL_DEADLINE_S = 900.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Root CA lifecycle: issue a leaf that verifies against the CA, revoke it, see it in an audit
    report, delete the bucket, then delete the CA. ACM PCA soft-deletes, so the CA stays readable
    and listed as DELETED and refuses updates."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc
    from botocore.exceptions import ClientError

    acm_pca = ctx.client("acm-pca")

    # ---- 1. Create a ROOT CA -------------------------------------------------
    common_name = ctx.unique_name("sim2real-acmpca-")[:64]
    create_resp = acm_pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": "root-ca-lifecycle"}],
    )
    ca_arn = create_resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _cleanup_ca(ctx, ca_arn))
    arn_prefix = f"arn:aws:acm-pca:{ctx.region}:{ctx.account}:certificate-authority/"
    assert ca_arn.startswith(arn_prefix) and len(ca_arn) > len(arn_prefix), (
        f"expected the CA ARN to start with {arn_prefix!r} followed by an id, got {ca_arn!r}"
    )

    status = _wait_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE", "FAILED"})
    assert status == "PENDING_CERTIFICATE", f"CA ended up {status} while awaiting a certificate"

    # ---- 2. Self-install the root certificate --------------------------------
    csr_pem = acm_pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    root_cert_arn = acm_pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=ROOT_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    root_cert_pem = _wait_for_certificate(ctx, ca_arn, root_cert_arn)

    acm_pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=root_cert_pem.encode("utf-8")
    )
    status = _wait_ca_status(ctx, ca_arn, {"ACTIVE", "FAILED"})
    assert status == "ACTIVE", f"CA did not become ACTIVE after import (status={status})"

    # ---- 3. Issue an end-entity certificate and verify it against the CA ------
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ee_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-ee.example.com")]))
        .sign(ee_key, hashes.SHA256())
    )
    ee_csr_pem = ee_csr.public_bytes(serialization.Encoding.PEM)

    ee_cert_arn = acm_pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=ee_csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    ee_cert_pem = _wait_for_certificate(ctx, ca_arn, ee_cert_arn)
    ee_cert = x509.load_pem_x509_certificate(ee_cert_pem.encode("utf-8"))

    ca_cert_pem = acm_pca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)["Certificate"]
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))
    ca_cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert ca_cn and ca_cn[0].value == common_name, (
        f"expected the installed CA certificate's subject CN to be {common_name!r}, got {ca_cert.subject.rfc4514_string()!r}"
    )
    assert ee_cert.issuer == ca_cert.subject, (
        f"expected the leaf issuer to equal the CA subject {ca_cert.subject.rfc4514_string()!r}, "
        f"got {ee_cert.issuer.rfc4514_string()!r}"
    )
    try:
        ca_cert.public_key().verify(
            ee_cert.signature,
            ee_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ee_cert.signature_hash_algorithm,
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"the issued leaf's signature does not verify against the CA public key: {exc!r}")
    ee_serial_hex = _serial_hex(ee_cert.serial_number)

    # ---- 4. Revoke the end-entity certificate --------------------------------
    acm_pca.revoke_certificate(
        CertificateAuthorityArn=ca_arn,
        CertificateSerial=ee_serial_hex,
        RevocationReason="UNSPECIFIED",
    )

    # ---- 5. Generate an audit report and confirm the revocation is recorded ----
    s3 = ctx.client("s3")
    bucket = _prepare_audit_bucket(ctx)
    audit = acm_pca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn, S3BucketName=bucket, AuditReportResponseFormat="JSON"
    )
    audit_status = _wait_audit_report(ctx, ca_arn, audit["AuditReportId"])
    assert audit_status == "SUCCESS", f"audit report ended in status={audit_status}"

    obj = s3.get_object(Bucket=bucket, Key=audit["S3Key"])
    entries = json.loads(obj["Body"].read())
    entry = next((e for e in entries if e.get("certificateArn") == ee_cert_arn), None)
    assert entry is not None, "issued end-entity certificate not present in audit report"
    assert entry.get("revokedAt"), "audit report does not show the certificate as revoked"
    assert entry.get("revocationReason") == "UNSPECIFIED", (
        f"expected revocationReason=UNSPECIFIED for the revoked end-entity cert, got {entry.get('revocationReason')!r}"
    )
    # Twin control: the root cert was never revoked, so the same report must show it as such;
    # this rules out a report generator that marks every row revoked.
    root_entry = next((e for e in entries if e.get("certificateArn") == root_cert_arn), None)
    assert root_entry is not None, "self-installed root certificate not present in audit report"
    assert not root_entry.get("revokedAt"), (
        f"never-revoked root certificate unexpectedly shows revokedAt in the audit report: {root_entry}"
    )

    # The audit bucket is emptied and deleted, then proven gone by id, by listing, and unusable.
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as err:
        head_status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    else:
        raise AssertionError(f"HeadBucket still answers for deleted audit bucket {bucket!r}")
    assert head_status == 404, f"expected HTTP 404 from HeadBucket on the deleted audit bucket, got {head_status!r}"
    names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    assert bucket not in names, f"deleted audit bucket {bucket!r} still listed by ListBuckets"
    try:
        s3.put_object(Bucket=bucket, Key="probe", Body=b"x")
    except ClientError as err:
        put_code = err.response["Error"]["Code"]
        put_status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        put_message = err.response["Error"].get("Message") or ""
    else:
        raise AssertionError(f"PutObject into deleted audit bucket {bucket!r} unexpectedly succeeded")
    assert put_code == "NoSuchBucket", f"expected NoSuchBucket for PutObject into the deleted bucket, got {put_code!r}"
    assert put_status == 404, f"expected HTTP 404 for PutObject into the deleted bucket, got {put_status!r}"
    expected_message = "The specified bucket does not exist"
    assert put_message == expected_message, f"expected the message {expected_message!r}, got {put_message!r}"

    # ---- 6. Disable then delete the CA, prove the tombstone and that it is unusable
    acm_pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    status = _wait_ca_status(ctx, ca_arn, {"DISABLED"})
    assert status == "DISABLED", f"expected CA status=DISABLED after UpdateCertificateAuthority, got {status!r}"

    acm_pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    # The soft-delete tombstone is the terminal by-id read.
    status = _wait_ca_status(ctx, ca_arn, {"DELETED"})
    assert status == "DELETED", f"expected CA status=DELETED after DeleteCertificateAuthority, got {status!r}"

    # During the restoration window the CA is listed only as DELETED.
    listed = _find_in_list(ctx, ca_arn)
    assert listed is not None, "CA vanished from ListCertificateAuthorities during its restoration window"
    assert listed["Status"] == "DELETED", f"expected listed CA status=DELETED, got {listed['Status']!r}"

    # A mutation on the DELETED CA is refused. AWS's message names the required states,
    # not the CA.
    try:
        result = acm_pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="ACTIVE")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        http_status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        message = err.response["Error"].get("Message") or ""
    else:
        raise AssertionError(f"UpdateCertificateAuthority on a DELETED CA unexpectedly succeeded: {result!r}")
    assert code == "InvalidStateException", (
        f"expected InvalidStateException rejecting UpdateCertificateAuthority on a DELETED CA, got {code!r}"
    )
    assert http_status == 400, f"expected HTTP 400 for the refused update on a DELETED CA, got {http_status!r}"
    expected_message = "The certificate authority must be in the ACTIVE or DISABLED state to be updated"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    after = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
    assert after == "DELETED", f"expected the refused update to leave the CA DELETED, got {after!r}"


def _wait_ca_status(ctx, ca_arn: str, target_statuses: set[str]) -> str:
    """Poll the CA until its status is in *target_statuses*; raises at the deadline."""
    acm_pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _POLL_DEADLINE_S
    status = None
    while time.monotonic() < deadline:
        status = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"CA never reached any of {sorted(target_statuses)} (last status {status!r})")


def _wait_for_certificate(ctx, ca_arn: str, cert_arn: str) -> str:
    from botocore.exceptions import ClientError

    acm_pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _POLL_DEADLINE_S
    while time.monotonic() < deadline:
        try:
            return acm_pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)[
                "Certificate"
            ]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(2)
    raise AssertionError(f"certificate {cert_arn} never became retrievable before the poll deadline")


def _serial_hex(serial_int: int) -> str:
    hex_str = format(serial_int, "x")
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def _prepare_audit_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-acmpca-audit-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; every other
    # region requires it. ctx.region drives it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_bucket(ctx, bucket))

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "root-ca-lifecycle"}]})
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
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
                        "aws:SourceAccount": ctx.account,
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
                "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _wait_audit_report(ctx, ca_arn: str, audit_report_id: str) -> str:
    """Poll the audit report to SUCCESS or FAILED; raises at the deadline."""
    acm_pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _POLL_DEADLINE_S
    status = None
    while time.monotonic() < deadline:
        status = acm_pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=audit_report_id
        )["AuditReportStatus"]
        if status in ("SUCCESS", "FAILED"):
            return status
        time.sleep(5)
    raise AssertionError(f"audit report {audit_report_id} never left CREATING (last status {status!r})")


def _empty_bucket(s3, bucket: str) -> None:
    token = None
    while True:
        kwargs = {"ContinuationToken": token} if token else {}
        resp = s3.list_objects_v2(Bucket=bucket, **kwargs)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        if not resp.get("IsTruncated"):
            return
        token = resp.get("NextContinuationToken")


def _cleanup_bucket(ctx, bucket: str) -> None:
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    try:
        _empty_bucket(s3, bucket)
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _find_in_list(ctx, ca_arn: str) -> Optional[dict]:
    acm_pca = ctx.client("acm-pca")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = acm_pca.list_certificate_authorities(**kwargs)
        for ca in resp.get("CertificateAuthorities", []):
            if ca["Arn"] == ca_arn:
                return ca
        token = resp.get("NextToken")
        if not token:
            return None


def _cleanup_ca(ctx, ca_arn: str) -> None:
    from botocore.exceptions import ClientError

    acm_pca = ctx.client("acm-pca")
    # Disable an ACTIVE CA, delete it, and return only once it is observed DELETED or gone.
    deadline = time.monotonic() + 420
    status = None
    while time.monotonic() < deadline:
        try:
            status = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
                "CertificateAuthority"
            ]["Status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "DELETED":
            return
        try:
            if status == "ACTIVE":
                acm_pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            elif status != "CREATING":
                acm_pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("InvalidStateException", "ConcurrentModificationException"):
                raise
        time.sleep(2)
    raise AssertionError(f"CA {ca_arn} never reached DELETED within 420 s (last status {status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
