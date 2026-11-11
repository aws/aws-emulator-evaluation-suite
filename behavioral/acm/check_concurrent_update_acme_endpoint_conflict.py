"""concurrent-update-acme-endpoint-conflict."""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-update-acme-endpoint-conflict"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two UpdateAcmeEndpoint calls racing one endpoint with opposite Contact values each succeed
    or lose with ConflictException, at least one succeeds, and the final Contact equals one
    successful racer's value, never a refused racer's."""
    acm = ctx.client("acm")
    arn = _create_public_acme_endpoint(ctx, contact="NOT_REQUIRED")
    _wait_for_endpoint_status(ctx, arn, {"ACTIVE"}, timeout_s=_cap(ctx, 120.0))

    contacts = ["REQUIRED", "NOT_REQUIRED"]
    outcomes = _race_two(
        lambda: acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact=contacts[0]),
        lambda: acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact=contacts[1]),
    )
    for o in outcomes:
        if o["code"] is None:
            continue
        assert o["code"] == "ConflictException", (
            f"a racing UpdateAcmeEndpoint may only lose with ConflictException, "
            f"got {o['code']} ({o['message']!r})"
        )
        expected = f"Concurrent modification of ACME endpoint {arn}. Please try again."
        assert o["message"] == expected, f"ConflictException message {o['message']!r}, expected {expected!r}"
    winners = [contacts[i] for i, o in enumerate(outcomes) if o["code"] is None]
    assert winners, f"at least one racing UpdateAcmeEndpoint must succeed: {outcomes}"

    # Settle the endpoint so DescribeAcmeEndpoint is not read mid-update.
    _wait_for_endpoint_status(ctx, arn, {"ACTIVE"}, timeout_s=_cap(ctx, 60.0))
    described = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert described["Contact"] in winners, (
        f"final Contact={described['Contact']!r} is not the value of a racer that succeeded "
        f"({winners!r}); outcomes={[o['code'] for o in outcomes]}"
    )


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _error_code_of(exc: BaseException) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict) and "Error" in resp:
        return resp["Error"].get("Code", type(exc).__name__)
    return type(exc).__name__


def _race_two(fn_a: Callable[[], Any], fn_b: Callable[[], Any]) -> list[dict[str, Any]]:
    """Fire fn_a and fn_b as close to simultaneously as possible; capture (code, result) each."""
    barrier = threading.Barrier(2)
    results: list[dict[str, Any]] = [{}, {}]

    def worker(idx: int, fn: Callable[[], Any]) -> None:
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        try:
            res = fn()
            results[idx] = {"code": None, "message": None, "result": res}
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            message = resp.get("Error", {}).get("Message") if isinstance(resp, dict) else str(exc)
            results[idx] = {"code": _error_code_of(exc), "message": message, "result": None}

    t1 = threading.Thread(target=worker, args=(0, fn_a))
    t2 = threading.Thread(target=worker, args=(1, fn_b))
    t1.start()
    t2.start()
    t1.join(timeout=45)
    t2.join(timeout=45)
    return results


def _wait_for_endpoint_status(
    ctx, arn: str, target_statuses: set[str], timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _create_public_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-acme-ep-")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = resp["AcmeEndpointArn"]

    def _cleanup() -> None:
        try:
            _wait_for_endpoint_status(ctx, arn, {"ACTIVE", "FAILED"}, timeout_s=90)
        except AssertionError:
            pass
        for _ in range(8):
            try:
                acm.delete_acme_endpoint(AcmeEndpointArn=arn)
                return
            except Exception as exc:  # noqa: BLE001
                code = _error_code_of(exc)
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException":
                    time.sleep(3)
                    continue
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
