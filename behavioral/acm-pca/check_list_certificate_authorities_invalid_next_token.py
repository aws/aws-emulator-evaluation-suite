"""list-certificate-authorities-invalid-next-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-certificate-authorities-invalid-next-token"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

def _err(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises, because an emulator accepting a token real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"a NextToken acm-pca never minted must be refused, but the call SUCCEEDED and "
        f"returned {result!r}"
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A NextToken not minted by acm-pca is rejected with InvalidNextTokenException."""
    pca = ctx.client("acm-pca")

    # Positive control: the unpaginated call must succeed on this account/credentials, so a
    # rejection below is attributable to the bogus token and not to every call to this API.
    baseline = pca.list_certificate_authorities(MaxResults=1)
    assert isinstance(baseline.get("CertificateAuthorities"), list), (
        f"baseline ListCertificateAuthorities(MaxResults=1) must return a "
        f"CertificateAuthorities list, got {baseline!r}"
    )

    error = _err(
        lambda: pca.list_certificate_authorities(
            MaxResults=1, NextToken="c2ltMnJlYWwtcHJvYmUtYm9ndXMtdG9rZW4="
        )
    )
    refusal = (error.get("Code"), error.get("Message"))
    assert refusal == (
        "InvalidNextTokenException",
        "The NextToken you provided is invalid. Use a token returned by ListCertificateAuthorities.",
    ), (
        f"expected InvalidNextTokenException for a NextToken acm-pca never minted, got {refusal!r} "
        f"(full error: {error!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
