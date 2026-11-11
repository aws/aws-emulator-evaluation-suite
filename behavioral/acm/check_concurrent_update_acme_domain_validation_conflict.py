"""concurrent-update-acme-domain-validation-conflict."""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-update-acme-domain-validation-conflict"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateAcmeDomainValidation calls with opposite DomainScopes each succeed or lose with
    ConflictException or the VALIDATING-status ValidationException, at least one succeeds, and the
    final DomainScope is one winner's scope in full, never a refused racer's or a merge."""
    acm = ctx.client("acm")
    endpoint_arn = _create_public_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, endpoint_arn, {"ACTIVE"}, timeout_s=_cap(ctx, 120.0))

    domain_name = f"{ctx.unique_name('sim2real-behav-')}.example.com".lower()
    validation_arn = _create_domain_validation(ctx, endpoint_arn, domain_name)

    # UpdateAcmeDomainValidation rejects requests with ValidationException while the record is
    # still actively VALIDATING; the validation is async, so bounded-poll until it settles into a
    # terminal status before racing the updates.
    _wait_for_dv_status(acm, validation_arn, {"VALID", "INVALID"}, timeout_s=_cap(ctx, 90.0))

    # DomainScope needs all three members, with exactly one of ExactDomain/Subdomains ENABLED.
    scope_a = {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"}
    scope_b = {"ExactDomain": "DISABLED", "Subdomains": "ENABLED", "Wildcards": "DISABLED"}
    scopes = [scope_a, scope_b]
    outcomes = _race_two(
        lambda: acm.update_acme_domain_validation(
            AcmeDomainValidationArn=validation_arn,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": scope_a}},
        ),
        lambda: acm.update_acme_domain_validation(
            AcmeDomainValidationArn=validation_arn,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": scope_b}},
        ),
    )
    # A successful update puts the record back into VALIDATING, so a racer served after the
    # winner is refused by the VALIDATING guard rather than by the conflict check.
    refusals = {
        "ConflictException": f"Concurrent modification of ACME domain validation {validation_arn}. Please try again.",
        "ValidationException": "Cannot update ACME domain validation in VALIDATING status.",
    }
    for o in outcomes:
        if o["code"] is None:
            continue
        assert o["code"] in refusals, (
            f"a racing UpdateAcmeDomainValidation may only lose with ConflictException or the "
            f"VALIDATING-status ValidationException, got {o['code']} ({o['message']!r})"
        )
        expected = refusals[o["code"]]
        assert o["message"] == expected, (
            f"{o['code']} message {o['message']!r}, expected {expected!r}"
        )
    winners = [scopes[i] for i, o in enumerate(outcomes) if o["code"] is None]
    assert winners, f"at least one racing UpdateAcmeDomainValidation must succeed: {outcomes}"

    described = acm.describe_acme_domain_validation(AcmeDomainValidationArn=validation_arn)[
        "AcmeDomainValidation"
    ]
    final_scope = described["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    final_view = {k: final_scope.get(k) for k in scope_a}
    assert final_view in winners, (
        f"final DomainScope={final_view!r} is not the scope of a racer that succeeded "
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


def _wait_for_dv_status(
    acm, arn: str, target_statuses: set[str], timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=arn)["AcmeDomainValidation"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    return last


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
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-cuadvc-ep-")}],
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


def _create_domain_validation(ctx, endpoint_arn: str, domain_name: str) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-cuadvc-dv-")}],
    )
    arn = resp["AcmeDomainValidationArn"]

    def _cleanup() -> None:
        for _ in range(8):
            try:
                acm.delete_acme_domain_validation(AcmeDomainValidationArn=arn)
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
