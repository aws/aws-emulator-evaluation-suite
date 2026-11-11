"""list-acme-endpoints-reflects-created-and-deleted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-acme-endpoints-reflects-created-and-deleted"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created AcmeEndpoint appears in ListAcmeEndpoints with the fields it was
    created with, and disappears after DeleteAcmeEndpoint, proving the list tracks live
    lifecycle state rather than being a cached/point-in-time snapshot."""
    acm = ctx.client("acm")
    contact = "NOT_REQUIRED"
    arn = _create_acme_endpoint(ctx, contact=contact)

    entries_after_create = _list_all_acme_endpoints(ctx)
    created = next((e for e in entries_after_create if e["AcmeEndpointArn"] == arn), None)
    assert created is not None, f"newly created endpoint {arn} missing from ListAcmeEndpoints"
    assert created["Status"] == "ACTIVE", (
        f"listed status {created['Status']!r}, expected ACTIVE"
    )
    assert created["Contact"] == contact, (
        f"listed contact {created['Contact']!r}, expected {contact!r}"
    )

    acm.delete_acme_endpoint(AcmeEndpointArn=arn)

    deadline = time.monotonic() + 120.0
    while True:
        arns_now = {e["AcmeEndpointArn"] for e in _list_all_acme_endpoints(ctx)}
        if arn not in arns_now:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"{arn} still present in ListAcmeEndpoints after deletion")
        time.sleep(3.0)


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_errors(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint_ignore_errors(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _list_all_acme_endpoints(ctx) -> list[dict]:
    acm = ctx.client("acm")
    entries: list[dict] = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_acme_endpoints(**kwargs)
        entries.extend(resp.get("AcmeEndpoints", []))
        token = resp.get("NextToken")
        if not token:
            break
    return entries


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
