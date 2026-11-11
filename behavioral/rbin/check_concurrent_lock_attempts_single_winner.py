"""concurrent-lock-attempts-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-lock-attempts-single-winner"
GROUP = "concurrency"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent LockRule calls with the same LockConfiguration on one unlocked rule all succeed
    (none gets a conflict error) and the rule ends locked with that configuration: relocking an
    already-locked rule is not a conflict."""
    rbin = ctx.client("rbin")

    rule_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-racelock-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: _unlock_or_delete_rule(ctx, rule_id))

    n_racers = 6

    def _attempt_lock(_: int) -> tuple[bool, str | None]:
        try:
            rbin.lock_rule(
                Identifier=rule_id,
                LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 7, "UnlockDelayUnit": "DAYS"}},
            )
            return True, None
        except Exception as err:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                return False, err.response["Error"]["Code"]
            raise

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_attempt_lock, range(n_racers)))

    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]

    # Relocking with an identical configuration is idempotent on real AWS: every
    # concurrent LockRule call against the same rule succeeds.
    assert len(successes) == n_racers, f"n_ok={len(successes)} of {n_racers}"
    assert len(failures) == 0, f"expected 0 failures, got {failures}"

    final = rbin.get_rule(Identifier=rule_id)
    assert final["LockState"] == "locked", f"expected LockState=locked, got {final.get('LockState')!r}"
    assert final["LockConfiguration"]["UnlockDelay"]["UnlockDelayValue"] == 7, (
        f"expected UnlockDelayValue=7, got {final['LockConfiguration']['UnlockDelay']['UnlockDelayValue']!r}"
    )


# ===== helpers =====
def _unlock_or_delete_rule(ctx, rule_id: str) -> None:
    """Teardown: start a locked rule's unlock delay, delete an unlocked one; a missing rule is gone."""
    from botocore.exceptions import ClientError

    rbin = ctx.client("rbin")
    try:
        state = rbin.get_rule(Identifier=rule_id).get("LockState")
        if state == "locked":
            rbin.unlock_rule(Identifier=rule_id)
        elif state != "pending_unlock":
            rbin.delete_rule(Identifier=rule_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

