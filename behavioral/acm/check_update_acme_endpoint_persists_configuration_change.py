"""update-acme-endpoint-persists-configuration-change."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-acme-endpoint-persists-configuration-change"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAcmeEndpoint's field change is durably reflected on the next Describe, not just
    accepted transiently."""
    acm = ctx.client("acm")

    endpoint_arn = _create_active_endpoint(ctx, acm, contact="NOT_REQUIRED")

    before = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert before["Contact"] == "NOT_REQUIRED", f"expected NOT_REQUIRED, got {before['Contact']!r}"
    updated_at_before = before["UpdatedAt"]
    created_at = before["CreatedAt"]

    acm.update_acme_endpoint(AcmeEndpointArn=endpoint_arn, Contact="REQUIRED")

    after = _poll_for_contact(acm, endpoint_arn, "REQUIRED")
    assert after["Contact"] == "REQUIRED", f"expected REQUIRED, got {after['Contact']!r}"
    assert after["UpdatedAt"] > updated_at_before, "UpdatedAt did not advance after UpdateAcmeEndpoint"
    assert after["CreatedAt"] == created_at, "CreatedAt must not change on UpdateAcmeEndpoint"
    # AuthorizationBehavior/CertificateAuthority remain untouched by the unrelated field update
    assert after["AuthorizationBehavior"] == "PRE_APPROVED", (
        f"expected untouched PRE_APPROVED, got {after['AuthorizationBehavior']!r}"
    )



def _delete_if_present(fn):
    """Teardown delete: return once it succeeds or the resource is already gone, retry a
    ConflictException while a dependent resource is still being released, raise the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NoSuchEntity"):
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _poll_for_contact(acm, arn: str, expected_contact: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if last["Contact"] == expected_contact:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"Contact never became {expected_contact!r}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
