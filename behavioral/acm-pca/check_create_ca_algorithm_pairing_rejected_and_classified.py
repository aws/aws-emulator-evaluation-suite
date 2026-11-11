"""create-ca-algorithm-pairing-rejected-and-classified."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-ca-algorithm-pairing-rejected-and-classified"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']


def _err(fn, ctx):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected success raises, after registering the created CA for cleanup."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    arn = result.get("CertificateAuthorityArn")
    if arn:
        ctx.on_cleanup(lambda: _delete_ca(ctx, arn))
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and created {arn!r}"
    )


def _delete_ca(ctx, ca_arn):
    try:
        ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _all_authorities(pca):
    """Every CA visible to the caller, including soft-DELETED ones."""
    out = []
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        out.extend(page.get("CertificateAuthorities", []))
    return out


def _common_names(pca):
    names = set()
    for ca in _all_authorities(pca):
        cn = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {}).get("CommonName")
        if cn:
            names.add(cn)
    return names


def _ca_body(common_name, key_algorithm, signing_algorithm, **extra):
    """A valid CreateCertificateAuthority body with the given algorithms and extra fields.

    UsageMode is SHORT_LIVED_CERTIFICATE, the cheaper tier; every call here should be refused."""
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": key_algorithm,
            "SigningAlgorithm": signing_algorithm,
            "Subject": {"CommonName": common_name},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
    }
    body.update(extra)
    return body


def _retrying(fn):
    """CreateCertificateAuthority has a low request-rate limit; retry throttles so a
    throttle is never mistaken for the validation outcome under test."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A SigningAlgorithm that does not match the KeyAlgorithm family is refused with
    InvalidArgsException in both directions and creates no CA, while a reserved tag key on a
    valid body gets the distinct InvalidTagException, so refusals are classified."""
    pca = ctx.client("acm-pca")
    marker = ctx.unique_name("sim2real-behav-pca-pair-").rstrip("-")
    cn_a, cn_b, cn_c = marker + "-a", marker + "-b", marker + "-c"

    # Liveness control: the service answers a well-formed read, so a rejection below is
    # a validation decision and not a dead endpoint.
    live = pca.list_certificate_authorities(MaxResults=1)
    assert "CertificateAuthorities" in live, f"ListCertificateAuthorities missing CertificateAuthorities: {live}"

    # EC key with an RSA signing algorithm.
    code_a, msg_a = _err(lambda: _retrying(
        lambda: pca.create_certificate_authority(**_ca_body(cn_a, "EC_prime256v1", "SHA256WITHRSA"))
    ), ctx)
    assert code_a == "InvalidArgsException", (
        f"EC_prime256v1 + SHA256WITHRSA must be refused with InvalidArgsException, got {code_a!r}"
    )
    assert msg_a == (
        "Signing algorithm SHA256WITHRSA cannot be used with key type EC_prime256v1. "
        "Valid signing algorithms are: SHA256WITHECDSA, SHA384WITHECDSA, SHA512WITHECDSA."
    ), f"unexpected pairing message: {msg_a!r}"

    # RSA key with an ECDSA signing algorithm, at SHA512 so a single-pair denylist does not pass.
    code_b, msg_b = _err(lambda: _retrying(
        lambda: pca.create_certificate_authority(**_ca_body(cn_b, "RSA_3072", "SHA512WITHECDSA"))
    ), ctx)
    assert code_b == "InvalidArgsException", (
        f"RSA_3072 + SHA512WITHECDSA must be refused with InvalidArgsException, got {code_b!r}"
    )
    assert msg_b == (
        "Signing algorithm SHA512WITHECDSA cannot be used with key type RSA_3072. "
        "Valid signing algorithms are: SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA, "
        "SHA256WITHRSA_PSS, SHA384WITHRSA_PSS, SHA512WITHRSA_PSS."
    ), f"unexpected pairing message: {msg_b!r}"

    # A valid pairing with a reserved tag key must get a tag-specific code, not the same
    # blanket InvalidArgsException.
    code_c, msg_c = _err(lambda: _retrying(
        lambda: pca.create_certificate_authority(
            **_ca_body(cn_c, "RSA_2048", "SHA256WITHRSA", Tags=[{"Key": "aws:reserved", "Value": "x"}])
        )
    ), ctx)
    assert code_c == "InvalidTagException", (
        f"a reserved 'aws:' tag key must be refused with InvalidTagException, got {code_c!r}"
    )
    assert msg_c == (
        "Tags starting with 'aws' are categorized as AWS internal tags and cannot be used "
        "for tagging in ACM Private CA service."
    ), f"unexpected reserved-tag message: {msg_c!r}"
    assert code_c != code_a, (
        "the pairing rejection and the tag rejection returned the same code "
        f"({code_a!r}); the request validator does not classify its refusals"
    )

    # DELETED CAs still appear in ListCertificateAuthorities, so even a soft-deleted
    # leftover from a refused create is caught here.
    names = _common_names(pca)
    for cn in (cn_a, cn_b, cn_c):
        assert cn not in names, (
            f"a refused CreateCertificateAuthority still produced an authority with "
            f"CommonName={cn!r}; refused requests must have no effect"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
