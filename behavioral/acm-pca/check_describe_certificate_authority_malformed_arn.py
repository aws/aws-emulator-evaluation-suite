"""describe-certificate-authority-malformed-arn."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-certificate-authority-malformed-arn"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

def _err(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCertificateAuthority with a CA ARN missing its resource id is rejected with
    InvalidArnException, while a well-formed call from the same client succeeds, so the rejection
    is about the malformed ARN."""
    pca = ctx.client("acm-pca")
    refusal = _err(
        lambda: pca.describe_certificate_authority(
            CertificateAuthorityArn=(
                f"arn:aws:acm-pca:{ctx.region}:000000000000:certificate-authority"
            )
        )
    )
    assert refusal == ("InvalidArnException", "Not a valid arn."), refusal

    live = pca.list_certificate_authorities(MaxResults=1)
    assert "CertificateAuthorities" in live, (
        f"ListCertificateAuthorities missing CertificateAuthorities: {live}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
