"""certificate-transparency-logging-preference-deprecated-field-ignored."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "certificate-transparency-logging-preference-deprecated-field-ignored"
GROUP = "lifecycle"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CT-logging preference defaults to ENABLED, and UpdateCertificateOptions (the only way to change it)
    is refused outright while the certificate is still PENDING_VALIDATION (not yet Issued/Valid) -- so the
    deprecated DISABLED opt-out can never be applied to a certificate that hasn't completed validation."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    domain = _domain(ctx, "ctlog")
    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: "Options" in d and d["Options"].get("CertificateTransparencyLoggingPreference"),
        timeout_s=60.0,
    )
    assert desc["Options"]["CertificateTransparencyLoggingPreference"] == "ENABLED", (
        "all new public certificates are recorded in a CT log by default"
    )

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

    desc2 = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc2["Options"]["CertificateTransparencyLoggingPreference"] == "ENABLED", (
        "the rejected DISABLED request must not have mutated the CT logging preference"
    )


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.example.com"


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
