"""leaf-issued-past-ca-notafter-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "leaf-issued-past-ca-notafter-rejected"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
# The CA certificate is deliberately given a SHORT life so a leaf can be asked to outlive it
# without asking for anything else unusual. Both leaf validities below are inside the 7-day
# ceiling short-lived-certificate mode imposes, so the ONLY rule the refused call breaks is
# the CA's own NotAfter -- the mode's ceiling is never the reason.
_CA_DAYS = 2
_LEAF_INSIDE_DAYS = 1
_LEAF_PAST_DAYS = 7


# The CA is tagged because its only handle is a server-minted UUID no name-prefix match reaches.


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
    """Decided BEFORE any create: an absent parser cannot be discovered after billing starts."""
    try:
        from cryptography import x509  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RequiredToolMissing(["cryptography"]) from exc


def _error(fn, *, what):
    """The botocore (Error.Code, Error.Message) fn() raises; raises on unexpected success."""
    try:
        resp = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"{what} was ACCEPTED rather than refused; the call returned {resp!r}. If a certificate "
        f"arn appears there, a certificate outliving its own issuer was signed and billed, and "
        f"ACM-PCA has no DeleteCertificate operation, so it can only expire."
    )


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED".

    Billing stops at the DELETED status, not at the delete call, so it polls for that status.
    """
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


def _create_ca(ctx, scenario, **overrides):
    """Create a CA and register its teardown AT CREATION TIME, before anything can assert."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": scenario}],
    }
    body.update(overrides)
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


def _activate_root_ca(ctx, ca_arn, validity, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR.

    The documented root-CA installation sequence (privateca userguide, "Install a root CA
    certificate"): GetCertificateAuthorityCsr -> IssueCertificate with the RootCACertificate/V1
    template against the CA's OWN arn -> GetCertificate -> ImportCertificateAuthorityCertificate.
    """
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
        Validity=validity,
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
    """An S3 bucket ACM-PCA may write into, with the teardown registered at create time."""
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


def _audit_rows(ctx, ca_arn, bucket, *, timeout_s):
    """Every certificate this CA has issued, as the audit report's own JSON rows.

    ACM-PCA models no ListCertificates operation, so the audit report is the ONLY enumeration
    of what a CA actually signed -- which is what makes it the effect-absent evidence for a
    refused issuance.
    """
    pca = ctx.client("acm-pca")
    s3 = ctx.client("s3")
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
        f"the audit report ended in {got.get('AuditReportStatus')!r}, so the effect-absent "
        f"assertion below has no evidence behind it"
    )
    body = s3.get_object(Bucket=got["S3BucketName"], Key=got["S3Key"])["Body"].read()
    return json.loads(body)


def _rsa_csr():
    """A locally generated RSA-2048 key and a PKCS#10 request for it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """An ACTIVE CA refuses a leaf that would outlive its CA certificate with ValidationException.
    A leaf inside the CA's NotAfter is issued, and the audit report lists only that leaf.

    Reference: https://docs.aws.amazon.com/privateca/latest/APIReference/API_IssueCertificate.html
    """
    _require_local_crypto()

    from cryptography import x509

    pca = ctx.client("acm-pca")
    timeout_s = 240
    scenario = "acm-pca-leaf-past-ca-notafter"

    bucket = _audit_bucket(ctx, scenario)
    ca_arn = _create_ca(ctx, scenario)
    ca_cert_pem = _activate_root_ca(
        ctx, ca_arn, {"Value": _CA_DAYS, "Type": "DAYS"}, timeout_s=timeout_s
    )
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("ascii"))
    ca_not_after = ca_cert.not_valid_after_utc

    csr_bytes = _rsa_csr().encode("ascii")

    # ---- positive control, established BEFORE anything is broken ----
    control_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_bytes,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": _LEAF_INSIDE_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    control_pem, _ = _await_certificate(ctx, ca_arn, control_arn, timeout_s=timeout_s)
    control = x509.load_pem_x509_certificate(control_pem.encode("ascii"))
    assert control.not_valid_after_utc < ca_not_after, (
        f"positive control leaf NotAfter {control.not_valid_after_utc.isoformat()} is not "
        f"inside the CA certificate's NotAfter {ca_not_after.isoformat()}, so the control does "
        f"not establish the boundary the refused call is supposed to cross"
    )

    # ---- break exactly one thing: ask for an end date past the CA's own NotAfter ----
    refusal = _error(
        lambda: pca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr_bytes,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn=_END_ENTITY_TEMPLATE,
            Validity={"Value": _LEAF_PAST_DAYS, "Type": "DAYS"},
        ),
        what=(
            f"IssueCertificate with a {_LEAF_PAST_DAYS}-day validity against a CA certificate "
            f"whose NotAfter is {ca_not_after.isoformat()}"
        ),
    )
    assert refusal == (
        "ValidationException",
        "The certificate validity specified exceeds the certificate authority validity.",
    ), (
        f"expected ValidationException when the requested leaf validity extends past the CA "
        f"certificate's NotAfter ({ca_not_after.isoformat()}), got {refusal!r}"
    )

    # ---- effect absent: the CA signed nothing but the control ----
    rows = _audit_rows(ctx, ca_arn, bucket, timeout_s=timeout_s)
    issued = [r for r in rows if r.get("templateArn") == _END_ENTITY_TEMPLATE]
    assert len(issued) == 1, (
        f"effect not absent: the audit report lists {len(issued)} EndEntityCertificate "
        f"issuances, expected only the control. Rows: "
        f"{[(r.get('serial'), r.get('notAfter'), r.get('templateArn')) for r in rows]!r}"
    )
    # Compared as integers, not strings: the report renders a serial as colon-separated hex
    # pairs, and a leading zero byte would make any textual comparison brittle.
    audited = {int(str(r.get("serial", "")).replace(":", ""), 16) for r in issued}
    assert audited == {control.serial_number}, (
        f"the audited issuance serials are {sorted(audited)!r} but the control certificate's "
        f"serial is {control.serial_number!r} -- the audited certificate is not the control, "
        f"so a certificate outliving the CA may have been signed after all"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
