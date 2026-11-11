"""revoked-leaf-appears-in-audit-report-with-reason."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "revoked-leaf-appears-in-audit-report-with-reason"
GROUP = 'data-plane'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7
_REASON = "KEY_COMPROMISE"


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _require_local_crypto():
    """Fail before any billable create if the cryptography package is missing."""
    try:
        from cryptography import x509  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RequiredToolMissing(["cryptography"]) from exc


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Disable then delete the CA, polling until Status == "DELETED", where billing stops."""
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 420
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn,
                PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: certificate authority {ca_arn} never reached "
        f"Status=DELETED within 420s (last observed {last_status!r}). It is STILL BILLING. "
        f"Delete it manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, scenario):
    """Create a root CA and register its teardown before anything can assert."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-rev-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": scenario}],
    }
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate, polling through RequestInProgressException until signing completes."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(
                CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=timeout_s, interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"], got.get("CertificateChain")


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR."""
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )

    def _csr_probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    csr_pem = _poll_until(
        _csr_probe, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]
    ca_cert_pem, _ = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


def _audit_bucket(ctx, scenario):
    """An S3 bucket ACM-PCA may write audit reports into."""
    s3 = ctx.client("s3")
    acct = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-pca-audit-").lower().rstrip("-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )

    def _empty_and_delete():
        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                        for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if objs:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AcmPcaWrite",
            "Effect": "Allow",
            "Principal": {"Service": "acm-pca.amazonaws.com"},
            "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketAcl",
                       "s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{bucket}/*", f"arn:aws:s3:::{bucket}"],
            "Condition": {
                "StringEquals": {"aws:SourceAccount": acct},
                "ArnLike": {"aws:SourceArn":
                            f"arn:aws:acm-pca:{ctx.region}:{acct}:certificate-authority/*"},
            },
        }],
    }))
    return bucket


def _rsa_csr(common_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """After RevokeCertificate, the audit report carries revokedAt and revocationReason only for
    the revoked serial, not for an untouched leaf from the same CA, and the revoked certificate
    is still retrievable, since revocation is not deletion.

    Reference: https://docs.aws.amazon.com/privateca/latest/userguide/PcaAuditReport.html
    """
    _require_local_crypto()

    from cryptography import x509

    pca = ctx.client("acm-pca")
    s3 = ctx.client("s3")
    timeout_s = 240
    scenario = "acm-pca-revocation-audit"

    bucket = _audit_bucket(ctx, scenario)
    ca_arn = _create_ca(ctx, scenario)
    _activate_root_ca(ctx, ca_arn, timeout_s=timeout_s)

    serials = {}
    for label in ("revoked", "control"):
        arn = pca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=_rsa_csr(f"sim2real-{label}").encode("ascii"),
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn=_END_ENTITY_TEMPLATE,
            Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
        )["CertificateArn"]
        pem, _ = _await_certificate(ctx, ca_arn, arn, timeout_s=timeout_s)
        serials[label] = x509.load_pem_x509_certificate(pem.encode("ascii")).serial_number
    assert serials["revoked"] != serials["control"], (
        f"the two issued certificates share serial {serials['revoked']!r}, so the control "
        f"cannot distinguish a targeted revocation from a blanket one"
    )

    # RevokeCertificate takes lowercase hex with no separators and refuses the colon-separated
    # form the audit report renders.
    pca.revoke_certificate(
        CertificateAuthorityArn=ca_arn,
        CertificateSerial=format(serials["revoked"], "x"),
        RevocationReason=_REASON,
    )

    report_id = pca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn, S3BucketName=bucket, AuditReportResponseFormat="JSON"
    )["AuditReportId"]
    got = _poll_until(
        lambda: pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=report_id
        ),
        lambda r: r.get("AuditReportStatus") in ("SUCCESS", "FAILED"),
        timeout_s=timeout_s, interval_s=3.0,
        description="audit report reaching a terminal status",
    )
    assert got["AuditReportStatus"] == "SUCCESS", (
        f"the audit report ended in {got.get('AuditReportStatus')!r}, so there is no evidence "
        f"of what the revocation did"
    )
    rows = json.loads(
        s3.get_object(Bucket=got["S3BucketName"], Key=got["S3Key"])["Body"].read()
    )
    # Keyed on the integer serial: the report renders serials as colon-separated hex pairs, so
    # a textual comparison would be brittle for a serial with a leading zero byte.
    by_serial = {int(str(r.get("serial", "")).replace(":", ""), 16): r for r in rows}

    assert serials["revoked"] in by_serial, (
        f"the audit report has no row for the revoked serial {serials['revoked']:x}; it lists "
        f"{[f'{s:x}' for s in by_serial]!r}"
    )
    assert serials["control"] in by_serial, (
        f"the audit report has no row for the untouched control serial "
        f"{serials['control']:x}; it lists {[f'{s:x}' for s in by_serial]!r}"
    )
    revoked_row = by_serial[serials["revoked"]]
    control_row = by_serial[serials["control"]]

    assert revoked_row.get("revocationReason") == _REASON, (
        f"the revoked certificate's audit row records revocationReason "
        f"{revoked_row.get('revocationReason')!r}, expected {_REASON!r}. Row: {revoked_row!r}"
    )
    assert revoked_row.get("revokedAt"), (
        f"the revoked certificate's audit row carries no revokedAt timestamp: {revoked_row!r}"
    )
    assert revoked_row.get("revokedAt") >= revoked_row.get("issuedAt"), (
        f"the revoked row's revokedAt {revoked_row.get('revokedAt')!r} precedes its issuedAt "
        f"{revoked_row.get('issuedAt')!r}"
    )

    assert "revokedAt" not in control_row and "revocationReason" not in control_row, (
        f"the leaf that was never revoked carries revocation state in its audit row: "
        f"{control_row!r} -- revocation was applied to the CA's whole issuance history rather "
        f"than to the serial RevokeCertificate was given"
    )

    revoked_arn = revoked_row["certificateArn"]
    still = pca.get_certificate(
        CertificateAuthorityArn=ca_arn, CertificateArn=revoked_arn
    )["Certificate"]
    assert x509.load_pem_x509_certificate(
        still.encode("ascii")
    ).serial_number == serials["revoked"], (
        f"GetCertificate for the revoked certificate returned a different serial; revocation "
        f"must not replace or remove the certificate"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
