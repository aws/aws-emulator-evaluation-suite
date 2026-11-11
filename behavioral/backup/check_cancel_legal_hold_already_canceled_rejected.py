"""cancel-legal-hold-already-canceled-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cancel-legal-hold-already-canceled-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Canceling an already canceled legal hold fails with InvalidResourceStateException and keeps
    the first cancellation's description and date; canceling an active hold succeeds."""
    backup = ctx.client("backup")

    vault_name = ctx.unique_name("sim2real-lh-vault-")
    backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-lh-vault"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    title = ctx.unique_name("sim2real-legalhold-")
    created = backup.create_legal_hold(
        Title=title,
        Description="behavioral fidelity check",
        RecoveryPointSelection={
            "VaultNames": [vault_name],
            "DateRange": {"FromDate": 0, "ToDate": time.time()},
        },
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-legalhold"},
    )
    hold_id = created["LegalHoldId"]

    # Wait for the freshly-created hold to reach ACTIVE before canceling it.
    _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=hold_id),
        lambda r: r["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )

    # Positive control: cancel the fresh, ACTIVE hold once -- must succeed.
    backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="first cancellation")
    first = _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=hold_id),
        lambda r: r["Status"] == "CANCELED",
        timeout_s=60,
        interval_s=2,
    )
    assert first["CancelDescription"] == "first cancellation", (
        f"expected CancelDescription='first cancellation' after the positive-control cancel, "
        f"got {first['CancelDescription']!r}"
    )

    # Negative: canceling the already-CANCELED hold again must be rejected.
    code, message = _error(
        lambda: backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="second cancellation")
    )
    assert code == "InvalidResourceStateException", (
        f"expected error code 'InvalidResourceStateException' when canceling an "
        f"already-CANCELED legal hold, got {code!r}"
    )
    assert message == (
        "Only ACTIVE legal holds can be canceled, the current state of provided legal hold is "
        "CANCELED."
    ), f"actual_message={message!r}"

    # Effect absent: the first cancellation's record must be unchanged.
    after = backup.get_legal_hold(LegalHoldId=hold_id)
    assert after["Status"] == "CANCELED", (
        f"expected Status='CANCELED' to remain after the rejected second cancellation, "
        f"got {after['Status']!r}"
    )
    assert after["CancelDescription"] == "first cancellation", (
        "second CancelLegalHold call overwrote the original cancellation record"
    )


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
