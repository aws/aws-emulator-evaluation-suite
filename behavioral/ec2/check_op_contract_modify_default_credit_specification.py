"""op-contract-modify-default-credit-specification."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-default-credit-specification"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-default-credit-specification")
def run(ctx) -> None:
    """ModifyDefaultCreditSpecification changes the account-level T-family default; DryRun rejects first."""
    ec2 = ctx.client("ec2")
    family = "t3a"

    original = ec2.get_default_credit_specification(InstanceFamily=family)[
        "InstanceFamilyCreditSpecification"
    ]["CpuCredits"]
    target = "unlimited" if original != "unlimited" else "standard"

    def _restore():
        ec2.modify_default_credit_specification(InstanceFamily=family, CpuCredits=original)

    ctx.on_cleanup(_restore)

    # --- error boundary: DryRun must reject before changing the setting ---
    code, msg = _error(
        lambda: ec2.modify_default_credit_specification(
            InstanceFamily=family, CpuCredits=target, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {msg!r}"

    # --- success path: flip the default and observe it via GetDefaultCreditSpecification ---
    resp = ec2.modify_default_credit_specification(InstanceFamily=family, CpuCredits=target)
    spec = resp["InstanceFamilyCreditSpecification"]
    assert spec["InstanceFamily"] == family
    assert spec["CpuCredits"] == target

    # This operation is asynchronous account-wide; give it a generous, bounded window to converge.

    try:
        settled = _poll_until(
            lambda: ec2.get_default_credit_specification(InstanceFamily=family)[
                "InstanceFamilyCreditSpecification"
            ]["CpuCredits"],
            lambda c: c == target,
            timeout_s=90.0,
            interval_s=5.0,
        )
    except AssertionError:
        raise AssertionError(
            "default credit specification did not converge within the polling window"
        )
    assert settled == target


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
