"""request-certificate-default-ct-logging-enabled."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "request-certificate-default-ct-logging-enabled"
GROUP = "lifecycle"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A certificate requested without any Options defaults to Certificate Transparency logging ENABLED."""
    acm = ctx.client("acm")
    domain = _domain(ctx, "ctdefault")
    arn = acm.request_certificate(
        DomainName=domain, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: "Options" in d and d["Options"].get("CertificateTransparencyLoggingPreference"),
        timeout_s=60.0,
    )
    assert desc["Options"]["CertificateTransparencyLoggingPreference"] == "ENABLED", (
        f"a certificate requested with no Options must default CT logging to ENABLED, "
        f"got {desc.get('Options')}"
    )
    assert desc["Status"] == "PENDING_VALIDATION", desc["Status"]
    assert desc["Type"] == "AMAZON_ISSUED", desc["Type"]


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
