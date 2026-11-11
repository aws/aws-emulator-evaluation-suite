"""concurrent-update-restore-testing-plan-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-restore-testing-plan-conflict"
GROUP = "concurrency"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Six concurrent UpdateRestoreTestingPlan calls on one plan: at least one succeeds, any loser
    gets ConflictException with its exact concurrent-update message, and the final
    ScheduleExpression is a successful racer's, never a refused racer's or a corrupted value."""
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real_rtp_").replace("-", "_")

    backup.create_restore_testing_plan(
        RestoreTestingPlan={
            "RestoreTestingPlanName": name,
            "RecoveryPointSelection": {
                "Algorithm": "LATEST_WITHIN_WINDOW",
                "RecoveryPointTypes": ["SNAPSHOT"],
                "IncludeVaults": ["*"],
            },
            "ScheduleExpression": "cron(0 5 ? * * *)",
        },
        Tags={"sim2real-concurrent-update-restore-testing-plan-conflict": name},
    )
    ctx.on_cleanup(lambda: backup.delete_restore_testing_plan(RestoreTestingPlanName=name))

    workers = 6
    barrier = threading.Barrier(workers)
    submitted = {f"cron(0 {i} ? * * *)" for i in range(workers)}

    def attempt(i: int):
        expr = f"cron(0 {i} ? * * *)"
        barrier.wait(timeout=30)
        try:
            backup.update_restore_testing_plan(
                RestoreTestingPlanName=name,
                RestoreTestingPlan={"ScheduleExpression": expr},
            )
            return ("ok", expr, None, None)
        except Exception as e:  # noqa: BLE001 - classify below
            code, message = _error_of(e)
            return ("err", expr, code, message)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(attempt, range(workers)))

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "err"]

    assert len(successes) >= 1, "no concurrent UpdateRestoreTestingPlan call succeeded"
    for _, _, code, message in errors:
        assert code == "ConflictException", f"unexpected error code for losing update: {code}"
        assert message == (
            f"Failed to update restore testing plan [{name}] due to an attempt to update it "
            "concurrently."
        ), f"actual_message={message!r}"

    # Poll (bounded) for the read to settle on one of the submitted values.
    winners = {expr for _, expr, _, _ in successes}
    timeout_s = 20.0
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 15.0))
    final_expr = _poll_until(
        lambda: backup.get_restore_testing_plan(RestoreTestingPlanName=name)["RestoreTestingPlan"][
            "ScheduleExpression"
        ],
        lambda expr: expr in submitted,
        timeout_s=timeout_s,
        interval_s=1.0,
    )
    assert final_expr in winners, (
        f"final ScheduleExpression {final_expr!r} is not the value of a racer that succeeded "
        f"({sorted(winners)}) -- a refused update applied or the race corrupted state"
    )


def _error_of(exc: Exception) -> tuple[str, str | None]:
    """Return a ClientError's (code, message)."""
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise exc


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
