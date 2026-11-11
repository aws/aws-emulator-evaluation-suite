"""put-policy-json-unicode-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-policy-json-unicode-round-trip"
GROUP = "representation"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy with unicode text round-trips through PutPolicy/GetPolicy with the text unescaped
    and the parsed structure identical; AWS re-serializes it, so whitespace is not preserved."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx, ctx.unique_name("pca-pol-"))
    _activate_root_ca(ctx, ca_arn)

    # AWS rejects a Principal account that does not exist and normalizes a bare account id
    # to its root ARN, so supply this account's root ARN for an exact structural comparison.
    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    principal_arn = f"arn:aws:iam::{own_account_id}:root"

    policy_dict = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Café-Zürich-Straße-Ñoño-Allow",
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": ["acm-pca:GetCertificate", "acm-pca:DescribeCertificateAuthority"],
                "Resource": ca_arn,
            }
        ],
    }
    # Pretty-printed with a trailing newline; AWS re-serializes it, so only content is compared.
    policy_text = json.dumps(policy_dict, indent=2, ensure_ascii=False) + "\n"

    acmpca.put_policy(ResourceArn=ca_arn, Policy=policy_text)
    ctx.on_cleanup(lambda: acmpca.delete_policy(ResourceArn=ca_arn))

    fetched = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]

    # The unicode text must appear verbatim, not re-encoded as \uXXXX escapes.
    assert "Café-Zürich-Straße-Ñoño-Allow" in fetched, (
        f"unicode text was altered/escaped in GetPolicy response: {fetched!r}"
    )
    assert "\\u" not in fetched, f"policy text was unicode-escaped: {fetched!r}"

    # Parsed structure and every value must be semantically identical to what was
    # sent, even though the surrounding whitespace/indentation is not preserved.
    fetched_dict = json.loads(fetched)
    assert fetched_dict == policy_dict, (
        f"policy round-trip changed structure/values:\nSENT={policy_dict!r}\nGOT={fetched_dict!r}"
    )


from botocore.exceptions import ClientError


def _call_with_retry(fn, retry_codes, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in retry_codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"timed out waiting for retry-able call; last error: {last_exc}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _create_root_ca(ctx, common_name):
    acmpca = ctx.client("acm-pca")
    config = {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"Country": "US", "Organization": "Sim2Real Test", "CommonName": common_name[:64]},
    }
    arn = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration=config,
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": "put-policy-json-unicode-round-trip"}],
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, arn))
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


def _safe_delete_ca(ctx, arn):
    """Disable an ACTIVE CA before deleting it; AWS rejects deleting an ACTIVE CA."""
    acmpca = ctx.client("acm-pca")

    def _status():
        return acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"]

    try:
        status = _status()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _poll_until(_status, lambda s: s == "DISABLED", timeout_s=60.0, interval_s=2.0)
    _call_with_retry(
        lambda: acmpca.delete_certificate_authority(
            CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
        ),
        retry_codes={"InvalidStateException"},
        timeout_s=60.0,
        interval_s=3.0,
    )


def _get_csr(ctx, arn):
    acmpca = ctx.client("acm-pca")
    return _call_with_retry(
        lambda: acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"],
        retry_codes={"RequestInProgressException"},
        timeout_s=60.0,
        interval_s=2.0,
    )


def _activate_root_ca(ctx, arn):
    """Self-signs the ROOT CA's own CSR and imports it -- the documented root
    activation flow (get CSR -> IssueCertificate w/ RootCACertificate/V1 template ->
    GetCertificate -> ImportCertificateAuthorityCertificate)."""
    acmpca = ctx.client("acm-pca")
    csr = _get_csr(ctx, arn)
    cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 365, "Type": "DAYS"},
    )["CertificateArn"]
    cert = _call_with_retry(
        lambda: acmpca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=cert_arn)[
            "Certificate"
        ],
        retry_codes={"RequestInProgressException"},
        timeout_s=60.0,
        interval_s=2.0,
    )
    _call_with_retry(
        lambda: acmpca.import_certificate_authority_certificate(
            CertificateAuthorityArn=arn, Certificate=cert.encode("utf-8")
        ),
        retry_codes={"RequestInProgressException", "ConcurrentModificationException"},
        timeout_s=60.0,
        interval_s=2.0,
    )
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return cert


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
