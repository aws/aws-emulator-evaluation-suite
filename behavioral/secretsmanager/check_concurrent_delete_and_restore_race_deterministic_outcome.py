"""concurrent-delete-and-restore-race-deterministic-outcome."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-and-restore-race-deterministic-outcome"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]

_MARKED_FOR_DELETION = "You can't perform this operation on the secret because it was marked for deletion."


def _refusal(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, so a target
    that serves a secret it reports as deleted fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until_stable(sm, name: str, timeout_s: float = 15.0, interval_s: float = 0.5, ctx=None) -> dict:
    """Poll DescribeSecret until the scheduled-for-deletion condition is observed identically
    on two consecutive reads, so a lagging replica can't be mistaken for a corrupted state."""
    deadline = time.monotonic() + timeout_s
    previous_condition = None
    previous_desc = None
    while time.monotonic() < deadline:
        desc = sm.describe_secret(SecretId=name)
        condition = "DeletedDate" in desc
        if previous_condition is not None and condition == previous_condition:
            return desc
        previous_condition = condition
        previous_desc = desc
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("DescribeSecret settling on a stable state: the run budget ended first; not graded")
    raise AssertionError(
        f"DescribeSecret never settled on a stable scheduled-for-deletion state within "
        f"{timeout_s}s (last observed: {previous_desc})"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Racing DeleteSecret and RestoreSecret calls on the same secret converge to one
    consistent final state with no intermediate corrupted metadata; a sequential delete and
    restore then grade the refusal and the recovered value on every run."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-delrestorerace-")

    sm.create_secret(Name=name, SecretString="stable-value", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    def do_delete():
        return sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)

    def do_restore():
        return sm.restore_secret(SecretId=name)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(do_delete), pool.submit(do_restore)]
        outcomes = []
        for fut in futures:
            try:
                fut.result()
                outcomes.append("ok")
            except Exception as exc:  # noqa: BLE001 - a losing racer may legitimately error
                outcomes.append(str(exc))

    # If neither call actually succeeded, the race never happened and the branches below would
    # trivially grade the untouched pre-race state -- so the race is only meaningful once at
    # least one side of it is known to have landed.
    assert "ok" in outcomes, f"neither DeleteSecret nor RestoreSecret succeeded during the race: {outcomes}"

    # Both calls already returned synchronously, but a read-path replica can lag briefly behind
    # the write path. Poll DescribeSecret until two consecutive reads agree on whether the
    # secret is scheduled for deletion, rather than sleeping a fixed duration and hoping.
    desc = _poll_until_stable(sm, name, timeout_s=_budget_s(ctx, 15.0), interval_s=0.5, ctx=ctx)

    if "DeletedDate" in desc:
        # Deletion won the race: metadata must be fully self-consistent as scheduled-for-deletion.
        assert desc["DeletedDate"] is not None, f"DeletedDate present but null in {desc!r}"
        code, message = _refusal(lambda: sm.get_secret_value(SecretId=name))
        assert code == "InvalidRequestException", (
            f"secret shows DeletedDate but GetSecretValue returned {code!r} instead of "
            "InvalidRequestException"
        )
        assert message == _MARKED_FOR_DELETION, (
            f"unexpected refusal message for a secret marked for deletion: {message!r}"
        )
        # Prove the state is genuinely recoverable (not corrupted) before final cleanup.
        sm.restore_secret(SecretId=name)
        restored = sm.describe_secret(SecretId=name)
        assert "DeletedDate" not in restored, "RestoreSecret after the race did not clear DeletedDate"
        got = sm.get_secret_value(SecretId=name)
        assert got["SecretString"] == "stable-value", (
            f"restored secret value corrupted: expected 'stable-value', got {got['SecretString']!r}"
        )
    else:
        # Restore won the race: metadata must be fully self-consistent as active.
        assert desc.get("DeletedDate") is None, f"DeletedDate unexpectedly present in {desc!r}"
        got = sm.get_secret_value(SecretId=name)
        assert got["SecretString"] == "stable-value", "active secret lost its value across the race"

    # Grade the scheduled-for-deletion surface on every run, whichever way the race resolved: the
    # secret is active here, so delete it in sequence, then restore it and read the value back.
    sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)
    deleted = sm.describe_secret(SecretId=name)
    assert deleted.get("DeletedDate") is not None, f"DeleteSecret did not set DeletedDate: {deleted!r}"
    code, message = _refusal(lambda: sm.get_secret_value(SecretId=name))
    assert code == "InvalidRequestException", (
        f"secret marked for deletion: GetSecretValue returned {code!r} instead of "
        "InvalidRequestException"
    )
    assert message == _MARKED_FOR_DELETION, (
        f"unexpected refusal message for a secret marked for deletion: {message!r}"
    )
    sm.restore_secret(SecretId=name)
    restored = sm.describe_secret(SecretId=name)
    assert "DeletedDate" not in restored, "RestoreSecret after the sequential delete did not clear DeletedDate"
    got = sm.get_secret_value(SecretId=name)
    assert got["SecretString"] == "stable-value", (
        f"restored secret value corrupted: expected 'stable-value', got {got['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
