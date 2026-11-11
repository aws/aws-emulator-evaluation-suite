"""acme-endpoint-directory-url-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-endpoint-directory-url-round-trip"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The AllowedKeyAlgorithms list supplied at CreateAcmeEndpoint round-trips exactly
    (same values, same order) via DescribeAcmeEndpoint, and the endpoint's system-assigned
    EndpointUrl is byte-identical across two independent describe calls."""
    acm = ctx.client("acm")
    algorithms = ["RSA_2048", "EC_prime256v1"]

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": algorithms}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-acme-endpoint-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    first = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"],
        lambda e: e["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert first["Status"] == "ACTIVE", f"endpoint failed to activate: {first.get('FailureReason')}"
    assert (
        first["CertificateAuthority"]["PublicCertificateAuthority"]["AllowedKeyAlgorithms"] == algorithms
    ), "AllowedKeyAlgorithms did not round-trip with the same values/order"
    url_first = first["EndpointUrl"]
    assert url_first, "EndpointUrl must be populated once the endpoint is ACTIVE"

    second = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert second["EndpointUrl"] == url_first, "EndpointUrl was not stable across repeated reads"
    second_algorithms = second["CertificateAuthority"]["PublicCertificateAuthority"]["AllowedKeyAlgorithms"]
    assert second_algorithms == algorithms, (
        f"AllowedKeyAlgorithms did not round-trip on the second read: expected {algorithms}, got {second_algorithms}"
    )


def _safe_call(fn) -> None:
    fn()


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
