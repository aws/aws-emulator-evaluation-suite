"""renew-certificate-concurrent-request-in-progress."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "renew-certificate-concurrent-request-in-progress"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent RenewCertificate calls on a never-issued (PENDING_VALIDATION) certificate all
    fail with ResourceNotFoundException and leave its status unchanged."""
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2realprobe')}.com"  # a random, non-reserved name stays PENDING_VALIDATION
    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))

    desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc["Status"] == "PENDING_VALIDATION", desc["Status"]

    def _attempt(_: int) -> tuple[str, str | None]:
        return _error(lambda: acm.renew_certificate(CertificateArn=arn))

    # RenewCertificate treats a certificate that was never issued as not found.
    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(_attempt, range(5)))
    codes = [code for code, _ in outcomes]
    messages = [message for _, message in outcomes]

    assert len(codes) == 5, f"expected 5 completed concurrent attempts, got {len(codes)}: {codes}"
    assert all(code == "ResourceNotFoundException" for code in codes), (
        f"expected all 5 concurrent renew_certificate calls to fail with "
        f"ResourceNotFoundException, got {codes}"
    )
    assert messages == [f"Could not find an issued certificate {arn}"] * 5, messages

    desc_after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc_after["Status"] == "PENDING_VALIDATION", desc_after["Status"]


def _error(fn: Any) -> tuple[str, str | None]:
    """The (code, message) of the ClientError fn raises, or ("SUCCEEDED", None) when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return "SUCCEEDED", None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
