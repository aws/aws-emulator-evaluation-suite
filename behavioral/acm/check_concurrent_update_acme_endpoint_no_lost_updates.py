"""concurrent-update-acme-endpoint-no-lost-updates."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-acme-endpoint-no-lost-updates"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """Two UpdateAcmeEndpoint calls racing one endpoint each succeed or lose with
    ConflictException, at least one succeeds, and DescribeAcmeEndpoint then reflects a
    successful writer's Contact, never a lost or unrequested value."""
    acm = ctx.client("acm")
    arn = _create_endpoint(ctx, contact="NOT_REQUIRED")
    _wait_for_endpoint_active(ctx, arn)

    def updater(contact: str) -> tuple[str, str, str | None]:
        try:
            acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact=contact)
            return ("ok", contact, None)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return (err.get("Code"), contact, err.get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(updater, "REQUIRED"), pool.submit(updater, "NOT_REQUIRED")]
        outcomes = [f.result() for f in futures]

    # Settle the endpoint so DescribeAcmeEndpoint is not read mid-update.
    _wait_for_endpoint_active(ctx, arn)

    winners = [contact for status, contact, _ in outcomes if status == "ok"]
    assert len(winners) >= 1, f"no concurrent UpdateAcmeEndpoint call succeeded: {outcomes}"
    for status, _, message in outcomes:
        if status == "ok":
            continue
        assert status == "ConflictException", f"unexpected rejection code: {status} ({message!r})"
        expected = f"Concurrent modification of ACME endpoint {arn}. Please try again."
        assert message == expected, f"ConflictException message {message!r}, expected {expected!r}"

    final_contact = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Contact"]
    assert final_contact in winners, (
        f"final Contact {final_contact!r} does not match any successful writer's "
        f"value {winners!r} -- the update was silently lost or corrupted"
    )


def _create_endpoint(ctx: Any, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-cul-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx: Any, arn: str, timeout_s: float = 180.0) -> dict:
    acm = ctx.client("acm")
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 15.0))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        status = endpoint["Status"]
        if status == "ACTIVE":
            return endpoint
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} failed: {endpoint.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint {arn} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
