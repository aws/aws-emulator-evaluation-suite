"""create-acme-endpoint-then-describe-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-acme-endpoint-then-describe-active"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeEndpoint immediately yields a describable, ACTIVE endpoint via DescribeAcmeEndpoint."""
    acm = ctx.client("acm")
    name = ctx.unique_name("acme-cda-")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = resp["AcmeEndpointArn"]
    assert arn.startswith("arn:aws:acm:") and ":acme-endpoint/" in arn, f"unexpected AcmeEndpointArn shape: {arn!r}"
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(acm, arn))

    endpoint = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"],
        lambda ep: ep["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert endpoint["Status"] == "ACTIVE", f"endpoint did not reach ACTIVE: {endpoint}"
    assert endpoint["AcmeEndpointArn"] == arn, f"expected arn {arn!r}, got {endpoint['AcmeEndpointArn']!r}"
    assert endpoint["AuthorizationBehavior"] == "PRE_APPROVED", (
        f"expected AuthorizationBehavior PRE_APPROVED, got {endpoint['AuthorizationBehavior']!r}"
    )
    assert endpoint["Contact"] == "NOT_REQUIRED", f"expected Contact NOT_REQUIRED, got {endpoint['Contact']!r}"
    assert endpoint["EndpointUrl"].startswith("https://"), (
        f"expected an https EndpointUrl, got {endpoint['EndpointUrl']!r}"
    )
    actual_algos = endpoint["CertificateAuthority"]["PublicCertificateAuthority"]["AllowedKeyAlgorithms"]
    assert actual_algos == ["EC_prime256v1"], f"expected AllowedKeyAlgorithms ['EC_prime256v1'], got {actual_algos!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_ignoring_not_found(acm, arn):
    from botocore.exceptions import ClientError

    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
