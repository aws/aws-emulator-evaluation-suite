"""template-arn-condition-gates-a-real-signed-issue-certificate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-arn-condition-gates-a-real-signed-issue-certificate"
GROUP = "permissions_boundaries"
SERVICES = ["acm-pca", "iam"]

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_ALLOWED_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_WITHHELD_TEMPLATE = "arn:aws:acm-pca:::template/CodeSigningCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7
_POLICY_NAME = "sim2real-acmpca-template-condition"

# Codes that mean "IAM has not converged yet", NOT "the control blocked". AccessDeniedException
# is in this set ONLY on the two legs that expect success, where a denial is indistinguishable
# from an unpropagated grant; the leg that expects a denial does not poll at all.
_UNCONVERGED = frozenset({
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "SignatureDoesNotMatch",
    "AccessDeniedException",
})

_ACTIVATE_TIMEOUT_S = 180.0
_LEAF_TIMEOUT_S = 90.0
# Widening an already-effective inline policy's condition can take several minutes to apply.
_PROPAGATION_TIMEOUT_S = 600.0
_AUDIT_TIMEOUT_S = 300.0
_TEARDOWN_TIMEOUT_S = 420.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """The captured AWS error (code, message), or a sentinel code that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    return "UNEXPECTED_SUCCESS", None


def _require_local_crypto() -> None:
    """Fail before any create if the CSR builder is missing, so nothing billable is left behind."""
    from cryptography import x509  # noqa: F401


def _client_for_credentials(ctx, access_key_id, secret_access_key, service):
    """A client signing AS the minted principal, against the same target as ctx.client()."""
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED"."""
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
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
        f"Status=DELETED within {_TEARDOWN_TIMEOUT_S}s (last observed {last_status!r}). It is "
        f"STILL BILLING. Delete it manually: UpdateCertificateAuthority(Status='DISABLED') "
        f"then DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, scenario):
    """Create a ROOT CA and register its teardown AT CREATION TIME."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")[:64]},
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
            throttles = ("ThrottlingException", "Throttling", "RequestLimitExceeded")
            if code in throttles and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _fetch_csr(ctx, ca_arn, *, timeout_s):
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    return _poll_until(
        _probe, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate (as the ADMIN), polling through RequestInProgressException."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=timeout_s, interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"]


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE via the documented install sequence."""
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0, description="CA reaching PENDING_CERTIFICATE",
    )
    csr_pem = _fetch_csr(ctx, ca_arn, timeout_s=timeout_s)
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]
    ca_cert_pem = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0, description="CA reaching ACTIVE",
    )
    return ca_cert_pem


def _new_csr(common_name):
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


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-acmpca-audit-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name):
    """Teardown-only. Narrowed to ClientError so a bug here surfaces instead of vanishing."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _apply_audit_bucket_policy(ctx, bucket_name, ca_arn):
    """The bucket policy ACM-PCA requires to write an audit report (privateca userguide,
    "Access policies for audit reports in Amazon S3"), scoped to this account and this CA.
    """
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PCAAuditWrite",
                "Effect": "Allow",
                "Principal": {"Service": "acm-pca.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketAcl",
                           "s3:GetBucketLocation"],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnEquals": {"aws:SourceArn": ca_arn},
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))


def _audit_rows(ctx, ca_arn, bucket):
    """Generate an audit report and return its parsed JSON rows.

    ACM-PCA has no ListCertificates, so the audit report is the only enumeration of issued certs.
    """
    pca = ctx.client("acm-pca")
    s3 = ctx.client("s3")
    report_id = pca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=ca_arn, S3BucketName=bucket, AuditReportResponseFormat="JSON"
    )["AuditReportId"]

    def _probe():
        got = pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=ca_arn, AuditReportId=report_id
        )
        status = got.get("AuditReportStatus")
        if status == "FAILED":
            raise AssertionError(
                f"the audit report {report_id} for {ca_arn} FAILED, so the effect-absent read "
                f"this check depends on cannot be made: {got!r}"
            )
        return got if status == "SUCCESS" else None

    done = _poll_until(
        _probe, lambda v: v is not None, timeout_s=_AUDIT_TIMEOUT_S, interval_s=10.0,
        description=f"audit report {report_id} reaching SUCCESS",
    )
    key = done["S3Key"]
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return json.loads(body)


def _issue_as(client, ca_arn, csr_pem, template):
    """IssueCertificate through `client` (which may be the restricted principal)."""
    return client.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=template,
        Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
    )["CertificateArn"]


def _put_condition_policy(ctx, user_name, ca_arn, allowed_templates):
    """Grant acm-pca:IssueCertificate on ca_arn, gated on acm-pca:TemplateArn."""
    ctx.client("iam").put_user_policy(
        UserName=user_name,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "acm-pca:IssueCertificate",
                "Resource": ca_arn,
                "Condition": {
                    "StringEquals": {"acm-pca:TemplateArn": list(allowed_templates)}
                },
            }],
        }),
    )


def _delete_user_and_keys(ctx, user_name):
    """Teardown-only, ordered: keys and inline policies must go before the user itself."""
    iam = ctx.client("iam")
    try:
        for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
        for name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
            iam.delete_user_policy(UserName=user_name, PolicyName=name)
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity policy conditioned on acm-pca:TemplateArn lets a signed IssueCertificate use the
    allowed template, denies another with AccessDeniedException and issues nothing for it (audit
    report), and allows the identical call once the condition is widened.
    """
    _require_local_crypto()

    iam = ctx.client("iam")
    scenario = "acm-pca-template-arn-condition"

    ca_arn = _create_ca(ctx, scenario)
    _activate_root_ca(ctx, ca_arn, timeout_s=_ACTIVATE_TIMEOUT_S)
    ca_status = _describe(ctx, ca_arn)["Status"]
    assert ca_status == "ACTIVE", (
        f"the CA must be ACTIVE before any authorization conclusion is drawn, or an "
        f"InvalidStateException would be mistaken for a denial; Describe reports {ca_status!r}"
    )

    bucket = _create_bucket(ctx)
    _apply_audit_bucket_policy(ctx, bucket, ca_arn)

    # ---- a principal allowed ONLY the end-entity template ----
    user_name = ctx.unique_name("sim2real-pca-tmplcond-")[:64]
    iam.create_user(
        UserName=user_name, Tags=[{"Key": "sim2real", "Value": scenario}]
    )
    ctx.on_cleanup(lambda: _delete_user_and_keys(ctx, user_name))
    _put_condition_policy(ctx, user_name, ca_arn, [_ALLOWED_TEMPLATE])
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    as_user = _client_for_credentials(
        ctx, key["AccessKeyId"], key["SecretAccessKey"], "acm-pca"
    )

    csr_pem = _new_csr("template-condition.sim2real.invalid")

    # ---- BEAT 1: positive control. The allowed template succeeds for THIS principal. ----
    # A denial here is indistinguishable from an unpropagated grant, so this leg polls for
    # success and RAISES if it never converges.
    allowed_arn_box: dict[str, str] = {}

    def _try_allowed():
        try:
            allowed_arn_box["arn"] = _issue_as(as_user, ca_arn, csr_pem, _ALLOWED_TEMPLATE)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return "UNEXPECTED_SUCCESS"

    first = _poll_until(
        _try_allowed, lambda c: c not in _UNCONVERGED,
        timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=5.0,
        description=(
            "the acm-pca:TemplateArn-conditioned grant becoming effective for a real signed "
            "IssueCertificate with the ALLOWED template"
        ),
    )
    assert first == "UNEXPECTED_SUCCESS", (
        f"positive control: the policy allows IssueCertificate with "
        f"{_ALLOWED_TEMPLATE} on this CA, so the real signed call must SUCCEED before any "
        f"denial below can be attributed to the TemplateArn condition; got {first!r}"
    )
    control_arn = allowed_arn_box["arn"]

    # ---- BEAT 2+3: break exactly one thing -- the TemplateArn -- and read the code ----
    denied, denied_message = _error(lambda: _issue_as(as_user, ca_arn, csr_pem, _WITHHELD_TEMPLATE))
    assert denied == "AccessDeniedException", (
        f"the identical IssueCertificate request, differing ONLY in TemplateArn "
        f"({_WITHHELD_TEMPLATE} instead of {_ALLOWED_TEMPLATE}), must be refused with "
        f"AccessDeniedException by the acm-pca:TemplateArn condition; got {denied!r}"
    )
    account_id = ca_arn.split(":")[4]
    expected_message = (
        f"User: arn:aws:iam::{account_id}:user/{user_name} is not authorized to perform: "
        f"acm-pca:IssueCertificate on resource: {ca_arn} because no identity-based policy "
        f"allows the acm-pca:IssueCertificate action"
    )
    assert denied_message == expected_message, denied_message

    # ---- BEAT 4: effect absent, via the only enumeration ACM-PCA offers ----
    rows = _audit_rows(ctx, ca_arn, bucket)
    templates = [r.get("templateArn") for r in rows]
    assert _ALLOWED_TEMPLATE in templates, (
        f"the audit report must contain the control certificate issued moments ago, or the "
        f"absence of the withheld one below proves nothing but a lagging report; the report "
        f"lists templates {templates!r}"
    )
    assert _WITHHELD_TEMPLATE not in templates, (
        f"the denied call must have issued NOTHING: the audit report for {ca_arn} lists a "
        f"certificate against {_WITHHELD_TEMPLATE}, so the refusal did not prevent the effect. "
        f"Report templates: {templates!r}"
    )

    # ---- BEAT 5: restore -- widen the condition to admit the withheld template ----
    _put_condition_policy(ctx, user_name, ca_arn, [_ALLOWED_TEMPLATE, _WITHHELD_TEMPLATE])

    # ---- BEAT 6: the IDENTICAL call now succeeds ----
    restored_box: dict[str, str] = {}

    def _try_withheld():
        try:
            restored_box["arn"] = _issue_as(as_user, ca_arn, csr_pem, _WITHHELD_TEMPLATE)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return "UNEXPECTED_SUCCESS"

    after = _poll_until(
        _try_withheld, lambda c: c not in _UNCONVERGED,
        timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=5.0,
        description=(
            "the WIDENED acm-pca:TemplateArn condition becoming effective for the previously "
            "refused template"
        ),
    )
    assert after == "UNEXPECTED_SUCCESS", (
        f"once {_WITHHELD_TEMPLATE} is added to the condition, the byte-identical request that "
        f"was refused above must succeed -- otherwise the denial was not the condition but a "
        f"blanket refusal of IssueCertificate for this principal; got {after!r}"
    )

    # ---- terminal read, at the consumer, through the ADMIN credential ----
    restored_arn = restored_box["arn"]
    assert restored_arn != control_arn, (
        f"the restored call must have produced a NEW certificate, not the control one: both "
        f"are {control_arn!r}"
    )
    restored_pem = _await_certificate(
        ctx, ca_arn, restored_arn, timeout_s=_LEAF_TIMEOUT_S
    )
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    restored_cert = x509.load_pem_x509_certificate(restored_pem.encode("ascii"))
    try:
        ekus = restored_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        raise AssertionError(
            f"the code-signing certificate the restored grant produced must carry an "
            f"extendedKeyUsage extension; the OIDs actually present are "
            f"{[e.oid.dotted_string for e in restored_cert.extensions]!r}"
        ) from None
    oids = [o.dotted_string for o in ekus]
    assert ExtendedKeyUsageOID.CODE_SIGNING.dotted_string in oids, (
        f"the certificate the restored grant produced must actually be a code-signing "
        f"certificate -- the template the condition was widened to admit -- so its "
        f"extendedKeyUsage must contain "
        f"{ExtendedKeyUsageOID.CODE_SIGNING.dotted_string}; it carries {oids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
