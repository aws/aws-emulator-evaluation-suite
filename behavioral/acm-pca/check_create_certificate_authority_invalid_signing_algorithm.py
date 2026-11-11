"""create-certificate-authority-invalid-signing-algorithm."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-certificate-authority-invalid-signing-algorithm"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

def _err(fn, ctx):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success registers the created authority for deletion and raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    arn = (result or {}).get("CertificateAuthorityArn")
    if arn:
        ctx.on_cleanup(lambda: ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
        ))
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and created {arn!r}")

def _common_names(pca):
    """Every CommonName visible via ListCertificateAuthorities, including soft-DELETED
    CAs (which still consume the account's CA slot and must still be counted absent)."""
    names = set()
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for authority in page.get("CertificateAuthorities", []):
            cn = authority.get("CertificateAuthorityConfiguration", {}).get("Subject", {}).get("CommonName")
            if cn:
                names.add(cn)
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A signing algorithm incompatible with the key type is rejected at request
    validation with InvalidArgsException (no CA is created)."""
    pca = ctx.client("acm-pca")

    # Liveness control: the service answers a well-formed read, so the rejection below
    # is a validation decision and not a dead endpoint.
    live = pca.list_certificate_authorities(MaxResults=1)
    assert "CertificateAuthorities" in live, f"ListCertificateAuthorities missing CertificateAuthorities: {live}"

    bad_cn = ctx.unique_name("sim2real-behav-badalgo-").rstrip("-")
    code, message = _err(
        lambda: pca.create_certificate_authority(
            CertificateAuthorityConfiguration={
                "KeyAlgorithm": "RSA_2048",
                "SigningAlgorithm": "SHA256WITHECDSA",
                "Subject": {"CommonName": bad_cn},
            },
            CertificateAuthorityType="ROOT",
        ),
        ctx,
    )
    assert code == "InvalidArgsException", (
        f"RSA_2048 + SHA256WITHECDSA must be refused with InvalidArgsException, got {code!r}"
    )
    assert message == (
        "Signing algorithm SHA256WITHECDSA cannot be used with key type RSA_2048. "
        "Valid signing algorithms are: SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA, "
        "SHA256WITHRSA_PSS, SHA384WITHRSA_PSS, SHA512WITHRSA_PSS."
    ), f"unexpected pairing message: {message!r}"

    # Effect absent: an independent read must show no authority was created for the
    # refused request, not even a soft-DELETED one.
    names = _common_names(pca)
    assert bad_cn not in names, (
        f"a refused CreateCertificateAuthority still produced an authority with "
        f"CommonName={bad_cn!r}; refused requests must have no effect"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
