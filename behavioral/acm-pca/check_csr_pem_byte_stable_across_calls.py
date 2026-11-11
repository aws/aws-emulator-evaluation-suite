"""csr-pem-byte-stable-across-calls."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "csr-pem-byte-stable-across-calls"
GROUP = "representation"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCertificateAuthorityCsr, called repeatedly for the same CA, returns
    byte-identical PEM every time -- the CSR is stored verbatim, not regenerated
    (which would perturb its signature/serial-like encoding) on each call."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx, ctx.unique_name("pca-csr-"))

    first = _get_csr(ctx, ca_arn)
    second = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    assert first == second, f"CSR changed between call 1 and 2:\n{first!r}\nvs\n{second!r}"

    # Freeze detector: keep reading for a bounded window and demand every read match the
    # first, so the invariant is proven over elapsed time rather than over two back-to-back
    # calls that could both land in the same cached response.
    prior = second
    reads_after_first = 1
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        time.sleep(1.0)
        current = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        assert current == prior, (
            f"CSR changed on read #{reads_after_first + 1} after {6.0}s window:\n"
            f"{prior!r}\nvs\n{current!r}"
        )
        prior = current
        reads_after_first += 1
    assert reads_after_first >= 3, (
        f"only completed {reads_after_first} post-creation reads within the 6s window; "
        "need at least 3 to demonstrate stability over time"
    )


from botocore.exceptions import ClientError


def _call_with_retry(fn, retry_codes, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in retry_codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"timed out waiting for retry-able call; last error: {last_exc}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _create_root_ca(ctx, common_name):
    acmpca = ctx.client("acm-pca")
    config = {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"Country": "US", "Organization": "Sim2Real Test", "CommonName": common_name[:64]},
    }
    arn = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration=config,
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": "csr-pem-byte-stable-across-calls"}],
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(
        lambda: acmpca.delete_certificate_authority(
            CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
        )
    )
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


def _get_csr(ctx, arn):
    acmpca = ctx.client("acm-pca")
    return _call_with_retry(
        lambda: acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"],
        retry_codes={"RequestInProgressException"},
        timeout_s=60.0,
        interval_s=2.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
