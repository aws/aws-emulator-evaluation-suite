"""legal-hold-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "legal-hold-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A legal hold transitions ACTIVE -> CANCELED; ListLegalHolds ("active and previous
    legal holds" per the API's own contract) keeps reporting it, with its status flipped
    to CANCELED and never reverting to ACTIVE."""
    backup = ctx.client("backup")
    title = ctx.unique_name("sim2real-legalhold-")

    now = time.time()
    created = backup.create_legal_hold(
        Title=title,
        Description="sim2real behavioral fidelity check legal hold",
        RecoveryPointSelection={
            "VaultNames": ["*"],
            "DateRange": {"FromDate": now - 3600, "ToDate": now},
        },
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-legalhold"},
    )
    hold_id = created["LegalHoldId"]

    def _cancel_if_active():
        try:
            status = backup.get_legal_hold(LegalHoldId=hold_id)["Status"]
            if status == "ACTIVE":
                backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="test-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cancel_if_active)

    active = _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=hold_id),
        lambda r: r["Status"] == "ACTIVE",
        timeout_s=60.0,
    )
    assert active["Title"] == title, f"Title mismatch: {active['Title']!r} != {title!r}"

    listed = _list_all_legal_holds(backup)
    matching = [h for h in listed if h["LegalHoldId"] == hold_id]
    assert len(matching) == 1, f"expected exactly one ListLegalHolds entry for {hold_id}, got {len(matching)}"
    assert matching[0]["Status"] == "ACTIVE", f"unexpected status in list: {matching[0]['Status']!r}"

    backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="behavioral-check-cancel")

    canceled = _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=hold_id),
        lambda r: r["Status"] == "CANCELED",
        timeout_s=60.0,
    )
    assert canceled["CancelDescription"] == "behavioral-check-cancel", (
        f"CancelDescription mismatch: {canceled['CancelDescription']!r} != 'behavioral-check-cancel'"
    )

    listed_after = _list_all_legal_holds(backup)
    active_after = [h for h in listed_after if h["LegalHoldId"] == hold_id and h["Status"] == "ACTIVE"]
    assert active_after == [], f"canceled hold {hold_id} still reports ACTIVE in ListLegalHolds"
    matching_after = [h for h in listed_after if h["LegalHoldId"] == hold_id]
    assert len(matching_after) == 1, (
        f"expected the canceled hold {hold_id} to remain listed (ListLegalHolds covers "
        f"'active and previous' holds), got {len(matching_after)} matches"
    )
    assert matching_after[0]["Status"] == "CANCELED", (
        f"unexpected post-cancel status in list: {matching_after[0]['Status']!r}"
    )


def _list_all_legal_holds(backup):
    holds = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = backup.list_legal_holds(**kwargs)
        holds.extend(page.get("LegalHolds", []))
        token = page.get("NextToken")
        if not token:
            return holds


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
