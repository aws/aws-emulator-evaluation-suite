"""acme-endpoint-create-describe-list."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-endpoint-create-describe-list"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeEndpoint config is retrievable via Describe and shows up in List results."""
    acm = ctx.client("acm")

    create_resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-cdl-")}],
    )
    arn = create_resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))

    endpoint = _poll_until_active(ctx, arn)
    assert endpoint["AuthorizationBehavior"] == "PRE_APPROVED", (
        f"expected AuthorizationBehavior PRE_APPROVED, got {endpoint['AuthorizationBehavior']!r}"
    )
    assert endpoint["Contact"] == "NOT_REQUIRED", f"expected Contact NOT_REQUIRED, got {endpoint['Contact']!r}"
    assert endpoint["CertificateAuthority"] == {
        "PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}
    }, f"CertificateAuthority did not round-trip, got {endpoint['CertificateAuthority']!r}"
    assert endpoint["EndpointUrl"].startswith("https://"), (
        f"expected EndpointUrl to be a server-generated https URL once ACTIVE, got {endpoint['EndpointUrl']!r}"
    )
    assert endpoint["AcmeEndpointArn"] == arn, f"expected ARN {arn!r}, got {endpoint['AcmeEndpointArn']!r}"

    found = _poll_until_listed(ctx, arn)
    assert found, f"expected {arn} to appear in ListAcmeEndpoints results"


def _poll_until_active(ctx, arn, timeout_s=120.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if last["Status"] == "ACTIVE":
            return last
        if last["Status"] == "FAILED":
            raise AssertionError(f"endpoint {arn} reached FAILED: {last.get('FailureReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached ACTIVE, last status={last and last['Status']}")


def _poll_until_listed(ctx, arn, timeout_s=60.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        next_token = None
        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            page = acm.list_acme_endpoints(**kwargs)
            if any(e["AcmeEndpointArn"] == arn for e in page.get("AcmeEndpoints", [])):
                return True
            next_token = page.get("NextToken")
            if not next_token:
                break
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
