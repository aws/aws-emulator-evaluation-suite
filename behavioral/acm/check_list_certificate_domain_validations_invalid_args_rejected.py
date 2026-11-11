"""list-certificate-domain-validations-invalid-args-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-certificate-domain-validations-invalid-args-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCertificateDomainValidations rejects a never-issued NextToken with ValidationException,
    while the same certificate still lists cleanly without the token."""
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-acm-lcdv-')}.example.com".lower()
    cert_arn = acm.request_certificate(
        DomainName=domain, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    def _bad_token_call() -> None:
        acm.list_certificate_domain_validations(
            CertificateArn=cert_arn, NextToken="not-a-real-pagination-token"
        )

    code, message = _error(_bad_token_call)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "Invalid next token."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # positive control: the same certificate still lists cleanly without the
    # bogus token, proving the certificate/domain state was not disturbed
    summaries = acm.list_certificate_domain_validations(CertificateArn=cert_arn)[
        "DomainValidationSummaryList"
    ]
    assert len(summaries) == 1, f"expected exactly 1 domain validation summary, got {summaries!r}"
    assert summaries[0]["DomainName"] == domain, (
        f"expected DomainName {domain!r}, got {summaries[0].get('DomainName')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
