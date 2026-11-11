"""e2e-requested-certificate-stays-pending-independent-of-acme-endpoint."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-requested-certificate-stays-pending-independent-of-acme-endpoint"
GROUP = "e2e"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A plain RequestCertificate for a domain with an ACME domain validation yields an
    AWS_MANAGED certificate without AcmeEndpointArn that stays PENDING_VALIDATION after the
    ACME domain validation and endpoint are deleted."""
    acm = ctx.client("acm")

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-e2e-issue-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    endpoint_status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120.0,
    )
    assert endpoint_status == "ACTIVE", f"expected endpoint ACTIVE, got {endpoint_status}"

    # A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
    # FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
    domain = f"{ctx.unique_name('sim2realacmedv').rstrip('-')}.com".lower()
    validation_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=validation_arn))
    )

    initial_dv = acm.describe_acme_domain_validation(AcmeDomainValidationArn=validation_arn)["AcmeDomainValidation"]
    assert initial_dv["Status"] in _LIVE_STATUSES, f"expected a live status, got {initial_dv['Status']}"
    assert initial_dv["DomainName"] == domain, f"expected domain {domain}, got {initial_dv['DomainName']}"

    cert_arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-e2e-issue-cert-")}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_certificate(CertificateArn=cert_arn)))

    cert = _wait_fully_populated(acm, cert_arn)
    assert cert["DomainName"] == domain, f"expected domain {domain}, got {cert['DomainName']}"
    assert cert["Status"] == "PENDING_VALIDATION", f"expected PENDING_VALIDATION, got {cert['Status']}"
    assert cert["DomainValidationOptions"][0]["ValidationStatus"] == "PENDING_VALIDATION", (
        f"expected PENDING_VALIDATION, got {cert['DomainValidationOptions'][0]['ValidationStatus']}"
    )
    assert cert["CertificateKeyPairOrigin"] == "AWS_MANAGED", (
        f"expected AWS_MANAGED (plain RequestCertificate must not inherit the ACME origin), "
        f"got {cert['CertificateKeyPairOrigin']!r}"
    )
    assert "AcmeEndpointArn" not in cert, (
        f"a plain RequestCertificate call must not carry an AcmeEndpointArn, got {cert.get('AcmeEndpointArn')!r}"
    )

    # Tear down the ACME validation + endpoint (dependents must go before the endpoint).
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=validation_arn)
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)

    # The certificate's state reflects the flow's real consequence: it was never tied
    # to the ACME endpoint's lifecycle, so it survives the teardown untouched.
    post_teardown_cert = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert post_teardown_cert["Status"] == "PENDING_VALIDATION", (
        f"expected PENDING_VALIDATION after ACME teardown, got {post_teardown_cert['Status']}"
    )
    assert post_teardown_cert["DomainName"] == domain, (
        f"expected domain {domain} after ACME teardown, got {post_teardown_cert['DomainName']}"
    )

    endpoint_gone_or_deleting = _poll_until(
        lambda: _acme_endpoint_status_or_gone(ctx, endpoint_arn),
        lambda s: s in ("DELETING", "GONE"),
        timeout_s=60.0,
    )
    assert endpoint_gone_or_deleting in ("DELETING", "GONE"), (
        f"expected endpoint DELETING or GONE, got {endpoint_gone_or_deleting}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _wait_fully_populated(acm, arn, *, timeout_s=30.0, interval_s=1.5):
    """DescribeCertificate once the record carries DomainName and a DomainValidationOptions entry
    with its ValidationStatus; for several seconds after RequestCertificate the Certificate can
    lack them, or the call can answer ResourceNotFoundException."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_cert = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval_s)
            continue
        last_cert = cert
        options = cert.get("DomainValidationOptions") or []
        if "DomainName" in cert and options and "ValidationStatus" in options[0]:
            return cert
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate {arn} never became fully populated within {timeout_s}s: "
        f"last_cert={last_cert!r} last_exc={last_exc!r}"
    )


def _acme_endpoint_status_or_gone(ctx, endpoint_arn):
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    try:
        return acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["Status"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
