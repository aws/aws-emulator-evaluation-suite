"""op-contract-update-certificate-options."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-update-certificate-options"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCertificateOptions on a PENDING_VALIDATION certificate refuses a ValidationMethod change
    ("Certificate is not issued") and an Export change with ValidationException and their exact
    messages, and the certificate's status, validation method and Export option stay unchanged."""
    acm = ctx.client("acm")
    domain = _domain(ctx)

    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="EMAIL",
        Options={"CertificateTransparencyLoggingPreference": "ENABLED"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))

    before = _wait_fully_populated(acm, arn)
    assert before["Status"] == "PENDING_VALIDATION", f"expected PENDING_VALIDATION, got {before['Status']}"
    assert before["DomainValidationOptions"][0]["ValidationMethod"] == "EMAIL", (
        f"expected EMAIL, got {before['DomainValidationOptions'][0]['ValidationMethod']}"
    )
    export_before = before["Options"].get("Export", "DISABLED")

    # boundary 1: cannot migrate the (renewal) validation method before the
    # certificate has been issued
    code_validation_method, message_validation_method = _error(
        lambda: acm.update_certificate_options(CertificateArn=arn, Options={"ValidationMethod": "DNS"})
    )
    assert code_validation_method == "ValidationException", (
        f"expected ValidationException, got {code_validation_method}"
    )
    assert message_validation_method == "Certificate is not issued", (
        f"expected message 'Certificate is not issued', got {message_validation_method!r}"
    )

    # boundary 2: likewise, Export cannot be toggled before the certificate is issued
    code_export, message_export = _error(
        lambda: acm.update_certificate_options(CertificateArn=arn, Options={"Export": "ENABLED"})
    )
    assert code_export == "ValidationException", f"expected ValidationException, got {code_export}"
    assert message_export == "Export option for certificates cannot be updated", (
        f"expected message 'Export option for certificates cannot be updated', got {message_export!r}"
    )

    # the forbidden effects did not happen: still pending, method/options unchanged
    still = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert still["Status"] == "PENDING_VALIDATION", f"expected PENDING_VALIDATION, got {still['Status']}"
    assert still["DomainValidationOptions"][0]["ValidationMethod"] == "EMAIL", (
        f"expected EMAIL, got {still['DomainValidationOptions'][0]['ValidationMethod']}"
    )
    export_after = still["Options"].get("Export", "DISABLED")
    assert export_after == export_before, f"expected Export unchanged at {export_before}, got {export_after}"


def _wait_fully_populated(acm, arn, *, timeout_s=30.0, interval_s=1.5):
    """DescribeCertificate once the record carries DomainName, Options and a
    DomainValidationOptions entry with its ValidationMethod; for several seconds after
    RequestCertificate the Certificate can lack them, or the call can answer
    ResourceNotFoundException."""
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
        if "DomainName" in cert and "Options" in cert and options and "ValidationMethod" in options[0]:
            return cert
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate {arn} never became fully populated within {timeout_s}s: "
        f"last_cert={last_cert!r} last_exc={last_exc!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
# FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
def _domain(ctx) -> str:
    return f"{ctx.unique_name('sim2real-acm-')}.com".lower()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
