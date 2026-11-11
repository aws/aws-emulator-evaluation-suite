"""acme-endpoint-create-active-delete-404."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-endpoint-create-active-delete-404"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ACME endpoint transitions CREATING->ACTIVE, DeleteAcmeEndpoint removes it, and a
    subsequent DescribeAcmeEndpoint returns ResourceNotFoundException."""
    acm = ctx.client("acm")

    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-cadd-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_quietly(acm, arn))

    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    assert status == "ACTIVE", f"endpoint entered {status} instead of ACTIVE"

    described = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert described["AcmeEndpointArn"] == arn, f"expected arn {arn}, got {described['AcmeEndpointArn']}"
    assert described["AuthorizationBehavior"] == "PRE_APPROVED", (
        f"expected AuthorizationBehavior PRE_APPROVED, got {described['AuthorizationBehavior']!r}"
    )
    assert described["Contact"] == "NOT_REQUIRED", f"expected Contact NOT_REQUIRED, got {described['Contact']!r}"
    assert described["EndpointUrl"].startswith("https://"), (
        f"expected an https EndpointUrl, got {described['EndpointUrl']!r}"
    )

    acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    code, message = _poll_until_endpoint_gone(acm, arn)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Could not find ACME endpoint {arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # independent side-channel: the deleted endpoint must not linger in ListAcmeEndpoints either
    listed_arns = set()
    next_token = None
    while True:
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = acm.list_acme_endpoints(**kwargs)
        listed_arns.update(e["AcmeEndpointArn"] for e in page.get("AcmeEndpoints", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert arn not in listed_arns, f"deleted endpoint {arn} must not appear in ListAcmeEndpoints"


def _delete_endpoint_quietly(acm, arn: str) -> None:
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _wait_for_endpoint_status(acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _poll_until_endpoint_gone(acm, arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> tuple:
    """Poll Describe until it is refused with ResourceNotFoundException; return that refusal's
    (code, message). Any other refusal (throttling, a 5xx) during propagation keeps polling."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return code, exc.response["Error"].get("Message")
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} not reported gone within {timeout_s}s (last result={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
