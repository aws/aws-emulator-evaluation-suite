"""list-certificate-domain-validations-nonexistent-cert-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-certificate-domain-validations-nonexistent-cert-not-found"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCertificateDomainValidations raises ResourceNotFoundException for a well-formed but
    nonexistent certificate ARN in the caller's account, while the same call on a real ARN
    succeeds, isolating the rejection to certificate existence."""
    acm = ctx.client("acm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    domain = f"{ctx.unique_name('sim2real-acm-nf-')}.example.com".replace("_", "-")
    real_arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=real_arn))

    # Positive control: the real certificate resolves fine.
    _assert_succeeds(
        lambda: acm.list_certificate_domain_validations(CertificateArn=real_arn),
        "real certificate ARN",
    )

    # Negative: same ARN shape/account, a certificate id that was never issued.
    fake_arn = f"arn:aws:acm:{ctx.region}:{account_id}:certificate/{uuid.uuid4()}"
    code, message = _refusal(
        lambda: acm.list_certificate_domain_validations(CertificateArn=fake_arn),
        "nonexistent certificate ARN",
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Could not find certificate {fake_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _assert_succeeds(fn, label: str) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        code = err.response["Error"]["Code"]
        raise AssertionError(f"{label} unexpectedly failed: {code}") from err


def _refusal(fn, label: str) -> tuple[str, str | None]:
    """The (code, message) of the ClientError fn raises; a success is a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"{label} unexpectedly succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
