"""list-certificate-domain-validations-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-certificate-domain-validations-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCertificateDomainValidations refuses an ARN naming no certificate with
    ResourceNotFoundException, lists a real certificate's validations, and refuses a malformed
    NextToken on it with ValidationException, each with its exact message."""
    acm = ctx.client("acm")

    # The account holds a certificate before the not-found call: an account that has never
    # held one is answered with an account-level message instead of the per-ARN one.
    domain = f"{ctx.unique_name('sim2real-acm-lcdv-').rstrip('-').lower()}.example.com"
    cert_arn = acm.request_certificate(
        DomainName=domain, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(ctx, cert_arn))

    nonexistent_arn = (
        f"arn:aws:acm:us-east-1:{ctx.account}:certificate/00000000-0000-0000-0000-000000000000"
    )
    code, message = _error(lambda: acm.list_certificate_domain_validations(CertificateArn=nonexistent_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Could not find certificate {nonexistent_arn}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a syntactically valid, existing certificate ARN succeeds and returns
    # the list shape

    resp = acm.list_certificate_domain_validations(CertificateArn=cert_arn)
    summaries = resp["DomainValidationSummaryList"]
    assert isinstance(summaries, list), f"expected a list, got {summaries!r}"

    # a malformed NextToken against that same, valid certificate is rejected as invalid input
    # (ValidationException) -- a malformed-token boundary distinct from the not-found boundary
    bad_token_code, bad_token_message = _error(
        lambda: acm.list_certificate_domain_validations(CertificateArn=cert_arn, NextToken="@@not-a-real-token@@")
    )
    assert bad_token_code == "ValidationException", f"expected ValidationException, got {bad_token_code!r}"
    assert bad_token_message == "Invalid next token.", f"expected 'Invalid next token.', got {bad_token_message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_certificate(ctx, arn):
    acm = ctx.client("acm")
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
