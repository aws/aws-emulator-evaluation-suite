"""create-certificate-authority-reserved-tag-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-certificate-authority-reserved-tag-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']
_CLEANUP_S = 300.0

# _retrying/_delete_ca use a SHORT_LIVED_CERTIFICATE CA that never issues a cert, a 7-day
# deletion window, and retries on CreateCertificateAuthority's low request-rate limit.


def _retrying(fn):
    for attempt in range(6):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    raise AssertionError("unreachable")


def _delete_ca(ctx, arn):
    # DeleteCertificateAuthority refuses a CREATING CA with InvalidStateException, so wait for the
    # CA to leave CREATING first.
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _CLEANUP_S
    try:
        while (
            pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
            == "CREATING"
        ):
            if time.monotonic() >= deadline:
                raise AssertionError(f"CA {arn} still CREATING after {_CLEANUP_S}s; cannot delete it")
            time.sleep(2.0)
        pca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _common_names(pca):
    names = set()
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for ca in page.get("CertificateAuthorities", []):
            cn = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {}).get("CommonName")
            if cn:
                names.add(cn)
    return names


def _ca_config(cn):
    return {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"CommonName": cn},
    }


# Reserved-prefix tag keys a direct caller cannot set. The aws:cloudformation: namespace is
# allowed only for requests CloudFormation makes on the caller's behalf, so a caller with
# ordinary credentials is rejected for it too.
_RESERVED_TAG_KEYS = ("aws:reserved", "aws:cloudformation:stack-id")
_RESERVED_TAG_MESSAGE = (
    "Tags starting with 'aws' are categorized as AWS internal tags and cannot be used for "
    "tagging in ACM Private CA service."
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority rejects a tag key with the reserved 'aws' prefix, including an
    aws:cloudformation: key from a direct caller, with InvalidTagException and creates no CA, while
    an ordinary tag key on the same call succeeds and reads back through ListTags."""
    pca = ctx.client("acm-pca")

    good_cn = ctx.unique_name("sim2real-behav-goodtag-").rstrip("-")
    good_arn = _retrying(
        lambda: pca.create_certificate_authority(
            CertificateAuthorityConfiguration=_ca_config(good_cn),
            CertificateAuthorityType="ROOT",
            UsageMode="SHORT_LIVED_CERTIFICATE",
            Tags=[{"Key": "Environment", "Value": "test"}],
        )
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, good_arn))
    tags_after = {t["Key"]: t["Value"] for t in pca.list_tags(CertificateAuthorityArn=good_arn)["Tags"]}
    assert tags_after.get("Environment") == "test", f"positive control tag missing: {tags_after}"

    rejected_cns = []
    for key in _RESERVED_TAG_KEYS:
        cn = ctx.unique_name("sim2real-behav-badtag-").rstrip("-")
        try:
            resp = _retrying(lambda cn=cn, key=key: pca.create_certificate_authority(
                CertificateAuthorityConfiguration=_ca_config(cn),
                CertificateAuthorityType="ROOT",
                UsageMode="SHORT_LIVED_CERTIFICATE",
                Tags=[{"Key": key, "Value": "x"}],
            ))
        except ClientError as exc:
            err = exc.response.get("Error", {})
            refusal = (err.get("Code"), err.get("Message", ""))
        else:
            # An over-permissive target actually created the CA -- register it for cleanup
            # right away so the defect the assert below reports does not also leak a
            # billable authority.
            arn = resp["CertificateAuthorityArn"]
            ctx.on_cleanup(lambda arn=arn: _delete_ca(ctx, arn))
            refusal = None
        assert refusal == ("InvalidTagException", _RESERVED_TAG_MESSAGE), f"{key}: {refusal}"
        rejected_cns.append(cn)

    # Effect absent: an independent read shows neither refused create left an authority
    # behind (the terminal read must be on a different operation than the one that
    # mutated -- CreateCertificateAuthority's own response is not enough).
    names = _common_names(pca)
    for cn in rejected_cns:
        assert cn not in names, (
            f"a refused CreateCertificateAuthority still produced an authority with "
            f"CommonName={cn!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
