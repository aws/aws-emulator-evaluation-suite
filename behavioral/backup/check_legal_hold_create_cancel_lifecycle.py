"""legal-hold-create-cancel-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "legal-hold-create-cancel-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLegalHold reaches ACTIVE, is listed, and CancelLegalHold drives it to CANCELED."""
    backup = ctx.client("backup")
    title = ctx.unique_name("sim2real-behav-lh-")

    created = backup.create_legal_hold(
        Title=title,
        Description="sim2real behavioral fidelity check legal hold",
        RecoveryPointSelection={
            "VaultNames": [ctx.unique_name("sim2real-behav-lhvault-")],
            "DateRange": {
                "FromDate": time.time() - (7 * 86400),
                "ToDate": time.time(),
            },
        },
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-lh"},
    )
    hold_id = created["LegalHoldId"]
    ctx.on_cleanup(lambda: _cancel_if_active(backup, hold_id))
    assert created["Status"] in ("CREATING", "ACTIVE"), (
        f"unexpected initial CreateLegalHold status: {created['Status']!r}"
    )

    status = _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=hold_id)["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=90.0,
    )
    assert status == "ACTIVE", f"expected ACTIVE after create, got {status!r}"

    # It must show up in ListLegalHolds (paginate defensively).
    seen_ids: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = backup.list_legal_holds(**kwargs)
        seen_ids.update(h["LegalHoldId"] for h in page.get("LegalHolds", []))
        token = page.get("NextToken")
        if not token:
            break
    assert hold_id in seen_ids, "created legal hold missing from ListLegalHolds"

    backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="fidelity check cleanup")

    final_status = _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=hold_id)["Status"],
        lambda s: s == "CANCELED",
        timeout_s=90.0,
    )
    assert final_status == "CANCELED", f"expected CANCELED after cancel, got {final_status!r}"

    # A subsequent GetLegalHold still reflects CANCELED (terminal state, no delete API).
    final = backup.get_legal_hold(LegalHoldId=hold_id)
    assert final["Status"] == "CANCELED", (
        f"expected CANCELED on independent re-read, got {final['Status']!r}"
    )


def _cancel_if_active(backup, hold_id):
    from botocore.exceptions import ClientError

    try:
        status = backup.get_legal_hold(LegalHoldId=hold_id)["Status"]
        if status == "ACTIVE":
            backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
