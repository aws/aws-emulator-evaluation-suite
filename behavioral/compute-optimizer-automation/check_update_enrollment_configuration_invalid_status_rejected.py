"""update-enrollment-configuration-invalid-status-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-enrollment-configuration-invalid-status-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """UpdateEnrollmentConfiguration rejects the server-only status value 'Pending' and leaves status unchanged."""
    client = ctx.client("compute-optimizer-automation")
    # Normalize to a caller-settable state first so "before"/the positive control below
    # is never itself the server-only 'Pending'/'Failed' state.
    _ensure_enrolled(ctx)
    before = client.get_enrollment_configuration()["status"]
    assert before == "Active", f"expected enrollment status 'Active' before the test, got {before!r}"

    # Break exactly one thing: 'Pending' is a server-derived status, not caller-settable.
    code, message = _client_error(lambda: client.update_enrollment_configuration(status="Pending"))
    assert code == "InvalidParameterValueException", (
        f"expected UpdateEnrollmentConfiguration(status='Pending') to be rejected with "
        f"'InvalidParameterValueException', got {code!r}"
    )
    expected_message = "Invalid status: Pending. Only ACTIVE and INACTIVE are allowed."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: enrollment status did not change because of the rejected call.
    after = client.get_enrollment_configuration()["status"]
    assert after == before, (
        f"the rejected update moved enrollment status from {before!r} to {after!r}"
    )

    # Positive control: re-affirming the current (valid) status succeeds. The mutating call's
    # own response is not the verdict — confirm it through an independent read.
    result = client.update_enrollment_configuration(status=before)
    assert result["status"] == before, (
        f"UpdateEnrollmentConfiguration(status={before!r}) returned status {result['status']!r}"
    )
    confirmed = client.get_enrollment_configuration()["status"]
    assert confirmed == before, (
        f"an independent read after the restore call saw status {confirmed!r}, expected {before!r}"
    )


# ===== helpers (self-contained) =====
def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses must not be collapsed into a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _ensure_enrolled(ctx) -> None:
    co = ctx.client("compute-optimizer")
    base_status = co.get_enrollment_status().get("status")
    if base_status != "Active":
        co.update_enrollment_status(status="Active", includeMemberAccounts=False)
        deadline0 = time.monotonic() + 120
        while time.monotonic() < deadline0:
            base_status = co.get_enrollment_status().get("status")
            if base_status == "Active":
                break
            if base_status == "Failed":
                raise AssertionError("compute-optimizer base enrollment failed")
            time.sleep(3)
        else:
            raise AssertionError(
                "compute-optimizer base enrollment did not reach Active within 120s",
            )

    client = ctx.client("compute-optimizer-automation")
    cfg = client.get_enrollment_configuration()
    if cfg["status"] == "Active":
        return
    if cfg["status"] in ("Inactive", "Pending", "Failed"):
        client.update_enrollment_configuration(status="Active")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        cfg = client.get_enrollment_configuration()
        if cfg["status"] == "Active":
            return
        if cfg["status"] == "Failed":
            raise AssertionError(f"account enrollment failed: {cfg.get('statusReason')}")
        time.sleep(2)
    raise AssertionError(
        "account did not reach Active Compute Optimizer Automation enrollment status "
        "within 60s of requesting UpdateEnrollmentConfiguration(status=Active)",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
