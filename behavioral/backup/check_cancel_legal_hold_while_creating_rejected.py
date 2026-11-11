"""cancel-legal-hold-while-creating-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-legal-hold-while-creating-rejected"
GROUP = "state-machine"
SERVICES = ["backup"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Fresh legal holds tried before the check gives up on observing the CREATING window.
_ATTEMPTS = 5
#: Bound on each wait for a hold to settle; the runner's remaining time bounds it further.
_SETTLE_TIMEOUT_S = 900.0
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-lhc"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelLegalHold on a hold still CREATING is refused with InvalidResourceStateException and its
    exact message, and the refused cancel leaves the hold to settle ACTIVE."""
    backup = ctx.client("backup")
    vault = ctx.unique_name("sim2real-lhc-vault-")
    backup.create_backup_vault(BackupVaultName=vault, BackupVaultTags=_TAGS)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault))

    expected = ("Only ACTIVE legal holds can be canceled, the current state of provided legal hold "
                "is CREATING.")
    tried = []
    hold_id = None
    for _ in range(_ATTEMPTS):
        created = backup.create_legal_hold(
            Title=ctx.unique_name("sim2real-lhc-"),
            Description="legal hold canceled while creating",
            RecoveryPointSelection={"VaultNames": [vault],
                                    "DateRange": {"FromDate": 0, "ToDate": time.time()}},
            Tags=_TAGS,
        )
        candidate = created["LegalHoldId"]
        ctx.on_cleanup(lambda h=candidate: _cancel(backup, h))
        assert created["Status"] == "CREATING", (
            f"CreateLegalHold answered Status {created['Status']!r}, expected 'CREATING'"
        )
        before = backup.get_legal_hold(LegalHoldId=candidate)["Status"]
        if before != "CREATING":
            tried.append(f"{candidate}: read {before!r} before the cancel")
            continue
        code, message, fields = _outcome(lambda: backup.cancel_legal_hold(
            LegalHoldId=candidate, CancelDescription="canceled while creating"))
        if (code, message) == ("InvalidResourceStateException", expected):
            modeled = (fields.get("Code"), fields.get("Context"))
            assert modeled == ("ERROR_22003", "CREATING"), (
                f"the refusal carried Code/Context {modeled!r}, "
                "expected ('ERROR_22003', 'CREATING')"
            )
            hold_id = candidate
            break
        after = backup.get_legal_hold(LegalHoldId=candidate)["Status"]
        assert after != "CREATING", (
            f"CancelLegalHold on a CREATING hold answered {code!r} {message!r}; expected "
            f"InvalidResourceStateException {expected!r}"
        )
        assert code == _ACCEPTED, f"CancelLegalHold answered {code!r} {message!r} once the hold was {after!r}"
        tried.append(f"{candidate}: cancel accepted after the hold left CREATING ({after!r})")
    assert hold_id, f"CancelLegalHold was never refused while CREATING in {_ATTEMPTS} holds: {tried!r}"

    left = ctx.time_left()
    timeout = _SETTLE_TIMEOUT_S if left is None else max(1.0, min(_SETTLE_TIMEOUT_S, left - min(60.0, left / 4)))
    settled = _settle(backup, hold_id, timeout)
    assert settled == "ACTIVE", f"after the refused cancel the hold settled {settled!r}, expected 'ACTIVE'"


def _outcome(fn) -> tuple[str, str | None, dict]:
    """(code, message, response) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer,
    the answer) when the target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message"), exc.response
    return _ACCEPTED, repr(result), result


def _settle(backup, hold_id: str, timeout: float = _SETTLE_TIMEOUT_S) -> str:
    """Poll until the hold leaves CREATING; returns the status reached."""
    deadline = time.monotonic() + timeout
    status = backup.get_legal_hold(LegalHoldId=hold_id)["Status"]
    while status == "CREATING":
        if time.monotonic() >= deadline:
            raise AssertionError(f"legal hold {hold_id} still CREATING after {timeout:.0f}s")
        time.sleep(5)
        status = backup.get_legal_hold(LegalHoldId=hold_id)["Status"]
    return status


def _cancel(backup, hold_id: str) -> None:
    """Cancel the hold once it is ACTIVE; a hold already canceling or canceled needs nothing."""
    if _settle(backup, hold_id) != "ACTIVE":
        return
    backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="teardown",
                             RetainRecordInDays=1)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
