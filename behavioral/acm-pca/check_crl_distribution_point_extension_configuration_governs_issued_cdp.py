"""crl-distribution-point-extension-configuration-governs-issued-cdp."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crl-distribution-point-extension-configuration-governs-issued-cdp"
GROUP = "server-side"
SERVICES = ["acm-pca"]

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7
_EXPIRATION_IN_DAYS = 5

_ACTIVATE_TIMEOUT_S = 180.0
_LEAF_TIMEOUT_S = 90.0
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


def _require_local_crypto() -> None:
    """Decided BEFORE any create: an absent parser cannot be discovered after billing starts."""
    from cryptography import x509  # noqa: F401


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying teardown that ends at an observed Status == "DELETED".

    An ACTIVE CA must be DISABLED before DeleteCertificateAuthority, and billing stops only at
    DELETED, so this polls for that status and raises if it never arrives.
    """
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


def _create_ca(ctx, scenario, **overrides):
    """Create a root CA and register its teardown at creation time, before anything asserts.

    Tagged because a CA's only handle is a server-minted UUID; the tag makes a stranded CA
    findable.
    """
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
    body.update(overrides)
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
    """GetCertificateAuthorityCsr, polling through the creation-in-progress guard."""
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
    """GetCertificate, polling through RequestInProgressException until signing completes.

    RequestInProgressException is the observable condition that signing is asynchronous --
    there is no sleep standing in for it. Returns (certificate_pem, chain_pem_or_None).
    """
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
    return got["Certificate"], got.get("CertificateChain")


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR.

    Follows the documented "Install a root CA certificate" sequence; returns the CA certificate PEM.
    """
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
    ca_cert_pem, _ = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


def _new_csr(common_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it; the key never leaves this
    process, so the issued certificate's public key is a falsifiable claim.
    """
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
    name = ctx.unique_name("sim2real-acmpca-crl-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; a
        # transport detail of the S3 API, not an environment assumption.
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


def _apply_pca_bucket_policy(ctx, bucket_name, ca_arns):
    """The bucket policy ACM-PCA requires to publish a CRL ("Access policies for CRLs in
    Amazon S3"), scoped to this account and these CAs.
    """
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
                    "ArnEquals": {"aws:SourceArn": list(ca_arns)},
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
                    "ArnEquals": {"aws:SourceArn": list(ca_arns)},
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))


def _expect_error_code(fn, description):
    """The captured AWS error (code, message). Raises on unexpected success, so an accepted call
    can never pass as a mere code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"{description} was expected to be REFUSED but it SUCCEEDED. An accepted call cannot "
        f"be graded as a wrong error code -- the control does not exist on this target"
    )


def _cdp_uris(cert):
    """The URI values of the certificate's cRLDistributionPoints, or [] if absent."""
    from cryptography import x509

    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []
    uris = []
    for point in ext.value:
        for name in point.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                uris.append(name.value)
    return uris


def _enable_crl(ctx, ca_arn, bucket, **extra):
    """Turn on CRL generation for ca_arn and wait until Describe reports it in effect."""
    cfg = {
        "Enabled": True,
        "ExpirationInDays": _EXPIRATION_IN_DAYS,
        "S3BucketName": bucket,
        "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL",
    }
    cfg.update(extra)
    ctx.client("acm-pca").update_certificate_authority(
        CertificateAuthorityArn=ca_arn, RevocationConfiguration={"CrlConfiguration": cfg}
    )
    return _poll_until(
        lambda: _describe(ctx, ca_arn).get("RevocationConfiguration", {}).get(
            "CrlConfiguration", {}
        ),
        lambda c: c.get("Enabled") is True,
        timeout_s=_ACTIVATE_TIMEOUT_S, interval_s=3.0,
        description=f"DescribeCertificateAuthority reporting CrlConfiguration.Enabled for {ca_arn}",
    )


def _issue_leaf(ctx, ca_arn, csr_pem):
    from cryptography import x509

    cert_arn = ctx.client("acm-pca").issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    pem, _ = _await_certificate(ctx, ca_arn, cert_arn, timeout_s=_LEAF_TIMEOUT_S)
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With CRL generation on, an issued certificate carries a CDP extension naming the configured
    bucket and region; a twin CA with OmitExtension=True issues the same CSR without it, and
    OmitExtension plus a CustomCname is refused (ValidationException) leaving the config unchanged.
    """
    _require_local_crypto()

    scenario = "acm-pca-cdp-extension-configuration"

    # Both CAs first, so both teardowns are registered before anything can assert.
    default_ca = _create_ca(ctx, scenario)
    omit_ca = _create_ca(ctx, scenario)
    bucket = _create_bucket(ctx)
    _apply_pca_bucket_policy(ctx, bucket, [default_ca, omit_ca])

    for arn in (default_ca, omit_ca):
        _activate_root_ca(ctx, arn, timeout_s=_ACTIVATE_TIMEOUT_S)

    default_cfg = _enable_crl(ctx, default_ca, bucket)
    assert default_cfg.get("CrlDistributionPointExtensionConfiguration") is None, (
        f"the default-configuration CA must carry NO "
        f"CrlDistributionPointExtensionConfiguration for its leg to test the documented "
        f"default; Describe reports {default_cfg!r}"
    )

    omit_cfg = _enable_crl(
        ctx, omit_ca, bucket,
        CrlDistributionPointExtensionConfiguration={"OmitExtension": True},
    )
    omit_echo = omit_cfg.get("CrlDistributionPointExtensionConfiguration", {})
    assert omit_echo.get("OmitExtension") is True, (
        f"OmitExtension must be observably stored before its effect on issued certificates is "
        f"graded: expected OmitExtension=True, Describe reports {omit_cfg!r}"
    )

    # ONE CSR for both legs.
    csr_pem = _new_csr("cdp.sim2real.invalid")
    default_leaf = _issue_leaf(ctx, default_ca, csr_pem)
    omit_leaf = _issue_leaf(ctx, omit_ca, csr_pem)

    # ---- Leg A: the documented default -- CDP present, pointing at THIS bucket ----
    default_uris = _cdp_uris(default_leaf)
    assert default_uris, (
        f"with CRL generation enabled and no CrlDistributionPointExtensionConfiguration, the "
        f"docs promise the CDP extension 'will be present and contain the default CRL URL': "
        f"expected at least one URI naming bucket {bucket!r}, the certificate carries "
        f"{default_uris!r} (all extension OIDs present: "
        f"{[e.oid.dotted_string for e in default_leaf.extensions]!r})"
    )
    joined = " ".join(default_uris)
    assert bucket in joined, (
        f"the default CDP URL must name the S3 bucket this run configured ({bucket!r}) -- the "
        f"docs say the CA 'copies the CNAME or the S3 bucket name to the CRL Distribution "
        f"Points extension'; the issued certificate points at {default_uris!r}"
    )
    assert ctx.region in joined, (
        f"the default CDP URL must name the region this run is signing in ({ctx.region!r}); "
        f"the issued certificate points at {default_uris!r}"
    )

    # ---- Leg B: OmitExtension=True -- CDP absent from the same CSR ----
    omit_uris = _cdp_uris(omit_leaf)
    assert omit_uris == [], (
        f"with OmitExtension=True the docs state 'the CDP extension will not be present in "
        f"any certificates issued by that CA'; this certificate carries {omit_uris!r}. The "
        f"twin CA above proves the extension IS emitted on this wiring when the field is "
        f"absent, so this is the field taking effect, not a target that never emits a CDP"
    )
    assert set(omit_uris) != set(default_uris), (
        f"the two CAs share a bucket, a CSR and a run and differ only in OmitExtension, so "
        f"their issued CDP extensions must differ: default={default_uris!r}, "
        f"omit={omit_uris!r}"
    )
    assert omit_leaf.serial_number != default_leaf.serial_number, (
        f"the two legs must be two distinct certificates, but both report serial "
        f"{default_leaf.serial_number:x}"
    )
    assert omit_leaf.issuer != default_leaf.issuer, (
        f"the two legs were issued by two DIFFERENT CAs, so their issuers must differ; both "
        f"report {default_leaf.issuer.rfc4514_string()!r}"
    )

    # ---- Leg C: the documented mutual exclusion with CustomCname ----
    cname = f"crl.{bucket}.sim2real.invalid"
    refusal = _expect_error_code(
        lambda: ctx.client("acm-pca").update_certificate_authority(
            CertificateAuthorityArn=omit_ca,
            RevocationConfiguration={
                "CrlConfiguration": {
                    "Enabled": True,
                    "ExpirationInDays": _EXPIRATION_IN_DAYS,
                    "S3BucketName": bucket,
                    "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL",
                    "CustomCname": cname,
                    "CrlDistributionPointExtensionConfiguration": {"OmitExtension": True},
                }
            },
        ),
        f"UpdateCertificateAuthority with both OmitExtension=True and CustomCname={cname!r}",
    )
    assert refusal == (
        "ValidationException",
        "You can't set a CustomCname if OmitExtension is set to true.",
    ), (
        f"OmitExtension 'cannot be enabled with a custom CNAME set', so the combination must "
        f"be refused with ValidationException (AWS's generic request-validation rejection -- "
        f"this constraint is not among UpdateCertificateAuthority's modelled business-logic "
        f"errors), with AWS's exact message; got {refusal!r}. The immediately preceding OmitExtension-without-CNAME update "
        f"on this same CA SUCCEEDED, so this is the combination being rejected and not the "
        f"field being unsupported"
    )

    # ---- effect absent: the refused update changed nothing ----
    after = _describe(ctx, omit_ca).get("RevocationConfiguration", {}).get(
        "CrlConfiguration", {}
    )
    assert after.get("CustomCname") is None, (
        f"the refused update must not have applied the CustomCname: Describe reports "
        f"{after!r}"
    )
    assert after.get("CrlDistributionPointExtensionConfiguration", {}).get(
        "OmitExtension"
    ) is True, (
        f"the refused update must have left the CA's prior OmitExtension=True configuration "
        f"intact: Describe reports {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
