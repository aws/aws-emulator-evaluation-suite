"""create-legal-hold-missing-required-field-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-legal-hold-missing-required-field-rejected"
GROUP = "error-semantics"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLegalHold without RecoveryPointSelection fails with MissingParameterValueException and
    creates no hold; the same call with a DateRange selection succeeds."""
    backup = ctx.client("backup")

    vault_name = ctx.unique_name("sim2real-lh-vault-")
    backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-lh-vault"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    rejected_title = ctx.unique_name("sim2real-legalhold-")
    code, message = _client_error(
        lambda: backup.create_legal_hold(
            Title=rejected_title,
            Description="behavioral fidelity check",
        )
    )
    assert code == "MissingParameterValueException", f"unexpected code: {code}"
    assert message == "Missing Resource Selection.", f"actual_message={message!r}"

    # The listing is account-wide, so the rejected call is graded by its own unique title.
    assert rejected_title not in _all_hold_titles(backup), (
        "a legal hold was created despite the missing-selector rejection"
    )

    # Positive control: adding a RecoveryPointSelection makes the call succeed.
    title = ctx.unique_name("sim2real-legalhold-")
    selection = {
        "VaultNames": [vault_name],
        "DateRange": {"FromDate": 0, "ToDate": time.time()},
    }
    created = backup.create_legal_hold(
        Title=title,
        Description="behavioral fidelity check",
        RecoveryPointSelection=selection,
        Tags={"sim2real:managed": "true"},
    )
    legal_hold_id = created["LegalHoldId"]
    ctx.on_cleanup(
        lambda: backup.cancel_legal_hold(
            LegalHoldId=legal_hold_id, CancelDescription="test cleanup"
        )
    )

    # Terminal assertion: an independent read (GetLegalHold, not CreateLegalHold's own
    # response) confirms the hold the positive control created actually exists and is live.
    fetched = _poll_legal_hold_settled(backup, legal_hold_id)
    assert fetched["Title"] == title, f"expected title {title!r}, got {fetched.get('Title')!r}"
    assert fetched["Status"] == "ACTIVE", f"unexpected status: {fetched.get('Status')!r}"
    # The same listing shows the created hold, so the absence above was read where a hold appears.
    assert title in _all_hold_titles(backup), f"ListLegalHolds does not list the created hold {title!r}"


def _all_hold_titles(backup) -> set:
    """Every legal hold title ListLegalHolds returns, across all pages."""
    titles, token = set(), None
    while True:
        page = backup.list_legal_holds(**({"NextToken": token} if token else {}))
        titles.update(h.get("Title") for h in page.get("LegalHolds", []))
        token = page.get("NextToken")
        if not token:
            return titles


def _poll_legal_hold_settled(backup, legal_hold_id, timeout_s=60.0, interval_s=2.0):
    """Poll GetLegalHold until the hold leaves the transient CREATING state; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = backup.get_legal_hold(LegalHoldId=legal_hold_id)
        if last["Status"] != "CREATING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"legal hold {legal_hold_id} still CREATING after {timeout_s}s: {last!r}")


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


