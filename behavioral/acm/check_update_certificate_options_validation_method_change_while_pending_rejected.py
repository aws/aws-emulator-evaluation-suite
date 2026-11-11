"""update-certificate-options-validation-method-change-while-pending-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-certificate-options-validation-method-change-while-pending-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCertificateOptions (the only supported Option is CertificateTransparencyLoggingPreference) is
    refused outright while a certificate is still PENDING_VALIDATION -- it may only be called once the
    certificate is Issued/Valid."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    domain = _domain(ctx, "vmethodreject")
    arn = acm.request_certificate(
        DomainName=domain, ValidationMethod="EMAIL", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("DomainValidationOptions"),
        timeout_s=60.0,
    )
    assert desc["Status"] == "PENDING_VALIDATION", desc["Status"]
    assert desc["DomainValidationOptions"][0]["ValidationMethod"] == "EMAIL", desc["DomainValidationOptions"]

    try:
        acm.update_certificate_options(
            CertificateArn=arn, Options={"CertificateTransparencyLoggingPreference": "DISABLED"}
        )
        raise AssertionError("UpdateCertificateOptions must be refused for a PENDING_VALIDATION certificate")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidStateException", err.response["Error"]["Code"]
        expected_message = "The selected certificate is not Issued and/or Valid."
        message = err.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert after["DomainValidationOptions"][0]["ValidationMethod"] == "EMAIL", (
        "the rejected UpdateCertificateOptions call must not have mutated the certificate"
    )


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.com"


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
