"""acme-endpoint-update-modifies-config."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-endpoint-update-modifies-config"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAcmeEndpoint mutates config and the change is visible on the next Describe."""
    acm = ctx.client("acm")

    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))

    before = _poll_until_active(ctx, arn)
    assert before["Contact"] == "NOT_REQUIRED", (
        f"expected initial Contact 'NOT_REQUIRED', got {before['Contact']!r}"
    )
    created_at = before["CreatedAt"]
    updated_at_before = before["UpdatedAt"]

    acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact="REQUIRED")

    after = _poll_until_contact(ctx, arn, expected="REQUIRED")
    assert after["Contact"] == "REQUIRED", (
        f"expected Contact 'REQUIRED' after UpdateAcmeEndpoint, got {after['Contact']!r}"
    )
    assert after["AuthorizationBehavior"] == "PRE_APPROVED", "unrelated field must be unchanged"
    assert after["CreatedAt"] == created_at, "CreatedAt must not change on update"
    assert after["UpdatedAt"] >= updated_at_before, "UpdatedAt must advance (or stay) after a mutation"


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


def _poll_until_contact(ctx, arn, expected, timeout_s=60.0, interval_s=2.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if last["Contact"] == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"Contact never became {expected!r}, last={last and last['Contact']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
