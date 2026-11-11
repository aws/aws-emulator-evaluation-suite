"""crl-next-update-derives-from-expiration-in-days."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "crl-next-update-derives-from-expiration-in-days"
GROUP = "server-side"
SERVICES = ["acm-pca"]

_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7

# Deliberately not a common default (1, 7, 14, 30) so a hardcoded CRL window is caught.
_EXPIRATION_IN_DAYS = 5
_CRL_PREFIX = "crl/"
# ACM-PCA backdates certificate notBefore by 60 minutes; allow the same skew on CRL timestamps.
_DELTA_TOLERANCE_S = 3600.0

_ACTIVATE_TIMEOUT_S = 180.0
# Bounds the first CRL publication, which AWS documents as typically within 30 minutes of
# configuring the CRL (Set up a CRL for AWS Private CA); the poll stays inside the run budget.
_CRL_POLL_TIMEOUT_S = 1500.0
_CRL_POLL_INTERVAL_S = 2.0


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
    """Fail before any create if the CRL parser is missing, so nothing billable is left behind."""
    try:
        from cryptography import x509  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RequiredToolMissing(["cryptography"]) from exc


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


# Inside the 900 s acm-pca cleanup budget, leaving room for the bucket teardown.
_CA_TEARDOWN_S = 780.0


def _delete_ca(ctx, arn):
    """Disable an ACTIVE CA, then delete it with the 7-day restoration period; retry the
    documented in-progress answers every 2 s to the deadline and raise on anything else."""
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + _CA_TEARDOWN_S
    while True:
        try:
            status = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
                "CertificateAuthority"
            ]["Status"]
            if status == "DELETED":
                return
            if status == "ACTIVE":
                acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
            acmpca.delete_certificate_authority(
                CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("InvalidStateException", "ConcurrentModificationException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"CA {arn} not deleted within {_CA_TEARDOWN_S}s: {exc}") from exc
        time.sleep(2)


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
    ctx.on_cleanup(lambda: _delete_ca(ctx, ca_arn))
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
    """GetCertificate, polling through RequestInProgressException until signing completes."""
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
    ca_cert_pem, _ = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0, description="CA reaching ACTIVE",
    )
    return ca_cert_pem


def _new_csr(common_name, dns_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _required_ext(obj, ext_class, what, where):
    """The extension's value, or an AssertionError naming the expected and present OIDs."""
    from cryptography import x509

    try:
        return obj.extensions.get_extension_for_class(ext_class).value
    except x509.ExtensionNotFound:
        present = [e.oid.dotted_string for e in obj.extensions]
        raise AssertionError(
            f"{where} must carry {what}, but the extension is absent; the OIDs actually "
            f"present are {present!r}"
        ) from None


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-acmpca-crl-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # CreateBucket rejects a LocationConstraint in us-east-1.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )
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


def _apply_pca_bucket_policy(ctx, bucket_name, ca_arn):
    """The bucket policy ACM-PCA requires in order to publish a CRL (privateca userguide,
    "Access policies for CRLs in Amazon S3"), scoped to this account and this CA.
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


def _await_published_crl(ctx, bucket, key):
    """Fetch and parse the DER CRL ACM-PCA publishes, polling until the object exists."""
    from cryptography import x509

    s3 = ctx.client("s3")

    def _probe():
        try:
            return x509.load_der_x509_crl(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        except ClientError:
            return None

    return _poll_until(
        _probe, lambda v: v is not None,
        timeout_s=min(_CRL_POLL_TIMEOUT_S, ctx.time_left() or _CRL_POLL_TIMEOUT_S), interval_s=_CRL_POLL_INTERVAL_S,
        description=f"ACM-PCA publishing a parseable DER CRL to s3://{bucket}/{key}",
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The published CRL's nextUpdate is thisUpdate + ExpirationInDays, thisUpdate is fresh, it is
    signed by the CA, carries a cRLNumber and matching AKI, and lists no revocations.

    Reference: https://docs.aws.amazon.com/privateca/latest/APIReference/API_CrlConfiguration.html
    """
    _require_local_crypto()

    from cryptography import x509

    pca = ctx.client("acm-pca")
    scenario = "acm-pca-crl-next-update-derivation"

    ca_arn = _create_ca(ctx, scenario)
    ca_cert_pem = _activate_root_ca(ctx, ca_arn, timeout_s=_ACTIVATE_TIMEOUT_S)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("ascii"))
    ca_id = ca_arn.rsplit("/", 1)[-1]

    bucket = _create_bucket(ctx)
    _apply_pca_bucket_policy(ctx, bucket, ca_arn)

    # The lower bound of the two-sided clock assertion. Captured BEFORE the CA is told to
    # publish CRLs at all, so no CRL that existed before this moment can satisfy it.
    before_enable = datetime.datetime.now(datetime.timezone.utc)

    pca.update_certificate_authority(
        CertificateAuthorityArn=ca_arn,
        RevocationConfiguration={
            "CrlConfiguration": {
                "Enabled": True,
                "ExpirationInDays": _EXPIRATION_IN_DAYS,
                "S3BucketName": bucket,
                "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL",
            }
        },
    )

    # The config must be observably in effect before anything is concluded from its effect.
    crl_cfg = _poll_until(
        lambda: _describe(ctx, ca_arn).get("RevocationConfiguration", {}).get(
            "CrlConfiguration", {}
        ),
        lambda c: c.get("Enabled") is True,
        timeout_s=_ACTIVATE_TIMEOUT_S, interval_s=3.0,
        description="DescribeCertificateAuthority reporting CrlConfiguration.Enabled=True",
    )
    assert crl_cfg["ExpirationInDays"] == _EXPIRATION_IN_DAYS, (
        f"the CA must report the ExpirationInDays that was configured before its effect on "
        f"the CRL is graded: expected {_EXPIRATION_IN_DAYS}, Describe reports "
        f"{crl_cfg['ExpirationInDays']!r}"
    )

    # Issuing one certificate is what makes the CA publish its first CRL.
    leaf_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=_new_csr("crl-window.sim2real.invalid", "crl-window.sim2real.invalid").encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    _await_certificate(ctx, ca_arn, leaf_arn, timeout_s=_ACTIVATE_TIMEOUT_S)

    crl = _await_published_crl(ctx, bucket, f"{_CRL_PREFIX}{ca_id}.crl")
    after_read = datetime.datetime.now(datetime.timezone.utc)

    # ---- the documented arithmetic: nextUpdate - thisUpdate == ExpirationInDays ----
    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    assert next_update is not None, (
        "the published CRL carries no nextUpdate field at all, so ExpirationInDays cannot "
        "have been used to calculate one"
    )
    delta_s = (next_update - this_update).total_seconds()
    want_s = _EXPIRATION_IN_DAYS * 86400.0
    assert abs(delta_s - want_s) <= _DELTA_TOLERANCE_S, (
        f"nextUpdate must be ExpirationInDays after thisUpdate: configured "
        f"ExpirationInDays={_EXPIRATION_IN_DAYS} means {want_s:.0f}s, but the published CRL "
        f"spans {delta_s:.0f}s ({delta_s / 86400.0:.3f} days) from thisUpdate={this_update} "
        f"to nextUpdate={next_update} -- outside the {_DELTA_TOLERANCE_S:.0f}s tolerance"
    )

    # ---- the two-sided live clock: a canned or replayed CRL cannot satisfy both bounds ----
    lower = before_enable - datetime.timedelta(seconds=_DELTA_TOLERANCE_S)
    assert this_update >= lower, (
        f"the CRL's thisUpdate {this_update} is older than the moment this run enabled CRL "
        f"publication ({before_enable}, less a {_DELTA_TOLERANCE_S:.0f}s skew allowance = "
        f"{lower}). A CRL that predates the configuration cannot have been generated from it "
        f"-- this is what a canned or replayed artifact looks like"
    )
    assert this_update <= after_read, (
        f"the CRL's thisUpdate {this_update} is in the future relative to the moment it was "
        f"read ({after_read}), so it was not issued by a clock this run can observe"
    )
    assert next_update > after_read, (
        f"the CRL must still be within its own validity window when read: nextUpdate is "
        f"{next_update} but the CRL was read at {after_read}"
    )

    # ---- recomputed cryptography: this CA signed this CRL ----
    assert crl.issuer == ca_cert.subject, (
        f"the published CRL's issuer is {crl.issuer.rfc4514_string()!r}, not the CA "
        f"certificate's subject {ca_cert.subject.rfc4514_string()!r}"
    )
    assert crl.is_signature_valid(ca_cert.public_key()), (
        f"the CRL at s3://{bucket}/{_CRL_PREFIX}{ca_id}.crl is structurally a CRL but its "
        f"signature does not verify under the public key of the CA certificate that was "
        f"imported to activate {ca_arn}"
    )

    # ---- the CRL-level extensions the docs promise ----
    crl_number = _required_ext(
        crl, x509.CRLNumber, "a cRLNumber extension", "the published CRL"
    ).crl_number
    assert crl_number >= 1, (
        f"the docs list 'X509v3 CRL Number: Decimal sequence number for the CRL' among the "
        f"CRL extensions; the published CRL reports crlNumber={crl_number!r}, which is not a "
        f"sequence number a first CRL could have"
    )
    aki = _required_ext(
        crl, x509.AuthorityKeyIdentifier, "an authorityKeyIdentifier extension",
        "the published CRL",
    )
    ca_ski = _required_ext(
        ca_cert, x509.SubjectKeyIdentifier, "a subjectKeyIdentifier extension",
        "the CA certificate",
    ).digest
    assert aki.key_identifier == ca_ski, (
        f"the CRL's authorityKeyIdentifier must identify the key that signed it: the CRL "
        f"carries {aki.key_identifier.hex()!r} but the CA certificate's subjectKeyIdentifier "
        f"is {ca_ski.hex()!r}"
    )

    # ---- nothing was revoked, so the list must be exactly empty ----
    revoked = [f"{entry.serial_number:x}" for entry in crl]
    assert revoked == [], (
        f"this check never called RevokeCertificate, so the published CRL's revoked list must "
        f"be empty; it names {revoked!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
