"""list-acme-endpoints-reflects-created."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-acme-endpoints-reflects-created"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created endpoint appears in ListAcmeEndpoints results."""
    acm = ctx.client("acm")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )

    found = _find_in_list(acm, arn)
    assert found is not None, f"created endpoint {arn} did not appear in ListAcmeEndpoints"
    assert found["AcmeEndpointArn"] == arn, f"listed ARN {found['AcmeEndpointArn']!r}, expected {arn!r}"
    assert found["Status"] == "ACTIVE", f"listed status {found['Status']!r}, expected ACTIVE"
    assert found["Contact"] == "REQUIRED", f"listed contact {found['Contact']!r}, expected REQUIRED"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _ignore_not_found(fn):
    """Run a teardown delete; only an already-gone resource is tolerated."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _find_in_list(acm, arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        next_token = None
        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            page = acm.list_acme_endpoints(**kwargs)
            for ep in page.get("AcmeEndpoints", []):
                if ep["AcmeEndpointArn"] == arn:
                    return ep
            next_token = page.get("NextToken")
            if not next_token:
                break
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
