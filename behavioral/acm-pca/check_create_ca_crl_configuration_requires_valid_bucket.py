"""create-ca-crl-configuration-requires-valid-bucket."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-ca-crl-configuration-requires-valid-bucket"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

# On AWS: the acm-pca Smithy model lists four errors for
# CreateCertificateAuthority (InvalidArgsException, InvalidPolicyException,
# InvalidTagException, LimitExceededException) and no revocation-specific error shape, but
# real acm-pca refuses every defective RevocationConfiguration with the UNMODELED, generic
# ValidationException instead -- including the semantic S3 lookup failure ("The S3 bucket you
# provided does not exist."), which is not a schema violation at all. The modeled
# service-specific codes are reserved for defects that get PAST that validation layer: a
# reserved 'aws:' tag prefix is InvalidTagException (the control below), an RSA/ECDSA
# mismatch is InvalidArgsException. Because the three breaks therefore share ONE code, each
# one additionally asserts the message fragment naming the specific rule it broke -- without
# that, an implementation could answer a bare ValidationException to anything.
_EXPECTED_CRL_REJECTION = "ValidationException"

# ===== helpers (self-contained) =====


def _err(fn, ctx):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. The
    message is load-bearing here: real acm-pca collapses every RevocationConfiguration
    defect onto one code and puts the specific rule in the message. An unexpected success
    registers the created authority for deletion and raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message") or ""
    arn = (result or {}).get("CertificateAuthorityArn")
    if arn:
        ctx.on_cleanup(lambda: ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
        ))
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and created {arn!r}")


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


def _common_names(pca):
    names = set()
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for ca in page.get("CertificateAuthorities", []):
            cn = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {}).get("CommonName")
            if cn:
                names.add(cn)
    return names


def _ca_body(common_name, revocation=None, tags_=None):
    """The valid GENERAL_PURPOSE baseline. GENERAL_PURPOSE rather than
    SHORT_LIVED_CERTIFICATE because short-lived CAs are documented as not supporting
    revocation at all, which would confound a CRL-validation refusal with a usage-mode
    refusal. Every call built from this body is expected to be REFUSED, so no CA of
    either tier is created."""
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "GENERAL_PURPOSE",
    }
    if revocation is not None:
        body["RevocationConfiguration"] = revocation
    if tags_ is not None:
        body["Tags"] = tags_
    return body


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An enabled CrlConfiguration is validated against S3 at CA-create time: a missing bucket,
    no bucket named, and ExpirationInDays over the maximum are each refused and no CA is created,
    while a DISABLED CRL block on the same body passes revocation validation."""
    pca = ctx.client("acm-pca")
    marker = ctx.unique_name("sim2real-behav-pca-crl-").rstrip("-")
    cn_a, cn_b, cn_c, cn_ctl = (marker + s for s in ("-a", "-b", "-c", "-ctl"))
    # A bucket name that is syntactically legal and certain not to exist. Never created.
    absent_bucket = marker.replace("_", "-").lower()[:63]

    # Break A -- CRL enabled against a bucket that does not exist. Exactly one thing is
    # wrong: the bucket is absent.
    code_a, msg_a = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_a, revocation={"CrlConfiguration": {
            "Enabled": True, "S3BucketName": absent_bucket, "ExpirationInDays": 7,
        }})
    )), ctx)
    assert code_a == _EXPECTED_CRL_REJECTION, (
        f"CRL enabled against the nonexistent bucket {absent_bucket!r} must be refused "
        f"with {_EXPECTED_CRL_REJECTION}, got {code_a!r}"
    )
    # The message proves PCA actually RESOLVED the bucket cross-service rather than rejecting
    # the field on its shape: "The S3 bucket you provided does not exist."
    assert msg_a == "The S3 bucket you provided does not exist.", (
        f"the bad-bucket refusal must report that the S3 bucket does not exist -- proving PCA "
        f"resolved it against S3 -- got {msg_a!r}"
    )

    # Break B -- CRL enabled with no bucket named at all. A CRL has nowhere to be
    # published, so the configuration is incomplete on its face.
    code_b, msg_b = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_b, revocation={"CrlConfiguration": {
            "Enabled": True, "ExpirationInDays": 7,
        }})
    )), ctx)
    assert code_b == _EXPECTED_CRL_REJECTION, (
        f"CRL enabled with no S3BucketName must be refused with "
        f"{_EXPECTED_CRL_REJECTION}, got {code_b!r}"
    )
    assert msg_b == (
        "1 validation error detected: Value null or empty at 's3BucketName' failed to "
        "satisfy constraint: Member must not be null or empty."
    ), (
        f"the missing-bucket refusal must name the s3BucketName member that is null or empty, "
        f"got {msg_b!r}"
    )
    assert msg_b != msg_a, (
        f"a missing bucket name and a nonexistent bucket are different defects but produced "
        f"the identical diagnostic {msg_a!r}"
    )

    # Break C -- ExpirationInDays above the modeled maximum (Integer1To5000, max 5000).
    # The lower bound (0) is NOT authorable here: botocore validates `min` client-side, so
    # 0 raises ParamValidationError before the request leaves the process; a client built
    # with Config(parameter_validation=False) would be needed to send it.
    code_c, msg_c = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_c, revocation={"CrlConfiguration": {
            "Enabled": True, "S3BucketName": absent_bucket, "ExpirationInDays": 5001,
        }})
    )), ctx)
    assert code_c == _EXPECTED_CRL_REJECTION, (
        f"ExpirationInDays=5001 exceeds the modeled maximum of 5000 and must be refused "
        f"with {_EXPECTED_CRL_REJECTION}, got {code_c!r}"
    )
    # Ordering fact: the range violation is caught BEFORE the (also invalid) bucket is
    # resolved, so this message is the range one and not the bad-bucket one.
    assert msg_c == (
        "1 validation error detected: Value at "
        "'revocationConfiguration.crlConfiguration.expirationInDays' failed to satisfy "
        "constraint: Member must have value less than or equal to 5000"
    ), (
        f"the over-range refusal must name expirationInDays and the 5000 bound it violated, "
        f"got {msg_c!r}"
    )

    # Control -- the SAME body with the CRL and OCSP blocks present but DISABLED is a
    # valid revocation configuration, so the request must get past revocation validation
    # and fail on the one other thing we broke (a reserved tag key). If this returns the
    # CRL rejection code instead, the emulator rejects the RevocationConfiguration field
    # wholesale rather than validating its contents, and Breaks A-C proved nothing.
    #
    # This substitutes for a positive control: an accepted CA with a valid CRL would mint a
    # metered private CA.
    code_ctl, msg_ctl = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(
            cn_ctl,
            revocation={"CrlConfiguration": {"Enabled": False},
                        "OcspConfiguration": {"Enabled": False}},
            tags_=[{"Key": "aws:reserved", "Value": "x"}],
        )
    )), ctx)
    assert msg_ctl == (
        "Tags starting with 'aws' are categorized as AWS internal tags and cannot be used "
        "for tagging in ACM Private CA service."
    ), (
        f"the control's refusal must be about the reserved 'aws' tag prefix, got {msg_ctl!r}"
    )
    assert code_ctl == "InvalidTagException", (
        f"a disabled CRL/OCSP block is a valid revocation configuration, so this request "
        f"must be refused for its reserved tag key (InvalidTagException), got {code_ctl!r}"
    )
    assert code_ctl != code_a, (
        f"the disabled-CRL control and the bad-bucket case returned the same code "
        f"({code_a!r}); revocation configuration is not being validated on its contents"
    )

    # Effect absent -- no authority from any of the four refused requests.
    names = _common_names(pca)
    for cn in (cn_a, cn_b, cn_c, cn_ctl):
        assert cn not in names, (
            f"a refused CreateCertificateAuthority still produced an authority with "
            f"CommonName={cn!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
