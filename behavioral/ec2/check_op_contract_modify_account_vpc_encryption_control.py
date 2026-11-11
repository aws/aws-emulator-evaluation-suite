"""op-contract-modify-account-vpc-encryption-control."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-account-vpc-encryption-control"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-vpc-encryption-control")
def run(ctx) -> None:
    """ModifyAccountVpcEncryptionControl updates the account-level mode; DryRun rejects first."""
    ec2 = ctx.client("ec2")

    original = ec2.describe_account_vpc_encryption_control()["AccountVpcEncryptionControl"]
    original_mode = original.get("Mode", "unmanaged")

    def _restore():
        ec2.modify_account_vpc_encryption_control(Mode=original_mode)

    ctx.on_cleanup(_restore)

    # --- error boundary: DryRun must reject before any setting is changed ---
    code, message = _error(lambda: ec2.modify_account_vpc_encryption_control(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message {message!r}"

    unchanged = ec2.describe_account_vpc_encryption_control()["AccountVpcEncryptionControl"]
    assert unchanged.get("Mode", "unmanaged") == original_mode, (
        "DryRun must not have modified the account VPC encryption control state"
    )

    # --- success path: switch to attempt-monitor (non-disruptive) and observe it stick ---
    target_mode = "attempt-monitor" if original_mode != "attempt-monitor" else "unmanaged"
    resp = ec2.modify_account_vpc_encryption_control(Mode=target_mode)
    control = resp["AccountVpcEncryptionControl"]
    assert control["Mode"] == target_mode, f"expected mode {target_mode!r}, got {control!r}"

    settled = _poll_until(
        lambda: ec2.describe_account_vpc_encryption_control()["AccountVpcEncryptionControl"],
        lambda c: c.get("Mode") == target_mode,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert settled["Mode"] == target_mode, f"expected mode {target_mode!r} to settle, got {settled!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
