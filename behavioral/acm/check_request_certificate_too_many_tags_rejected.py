"""request-certificate-too-many-tags-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "request-certificate-too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestCertificate accepts exactly 50 tags but is rejected outright (no cert created) at 51."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")

    # Positive control: exactly the 50-tag limit is accepted and the certificate is created with all of them.
    ok_domain = _domain(ctx, "tagok")
    ok_tags = [{"Key": f"{ctx.unique_name('acm-tagcap-')}-{i}", "Value": "v"} for i in range(50)]
    ok_arn = acm.request_certificate(DomainName=ok_domain, ValidationMethod="DNS", Tags=ok_tags)["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, ok_arn))
    got_tags = acm.list_tags_for_certificate(CertificateArn=ok_arn)["Tags"]
    assert len(got_tags) == 50, len(got_tags)

    # Negative: 51 tags exceeds the limit and the request must fail before any certificate is created.
    # ACM enforces the 50-tag maximum as a request-shape constraint (ValidationException), distinct from
    # TooManyTagsException (which applies to *modifying* the tag set of an already-existing resource).
    bad_domain = _domain(ctx, "tagtoomany")
    bad_tags = [{"Key": f"{ctx.unique_name('acm-tagcap2-')}-{i}", "Value": "v"} for i in range(51)]
    try:
        acm.request_certificate(DomainName=bad_domain, ValidationMethod="DNS", Tags=bad_tags)
        raise AssertionError("RequestCertificate with 51 tags must be rejected")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationException", err.response["Error"]["Code"]
        expected = (
            "1 validation error detected: Value of the input at 'tags' failed to satisfy "
            "constraint: Member must have length less than or equal to 50"
        )
        assert err.response["Error"].get("Message") == expected, err.response["Error"].get("Message")

    resp = acm.list_certificates(CertificateStatuses=["PENDING_VALIDATION"], MaxItems=1000)
    domains = {s["DomainName"] for s in resp.get("CertificateSummaryList", [])}
    assert bad_domain not in domains, "a certificate must not have been created for the rejected request"


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.example.com"


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
