"""update-framework-concurrent-conflict-detected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-framework-concurrent-conflict-detected"
GROUP = "concurrency"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two UpdateFramework calls fired concurrently against the same FrameworkName
    result in exactly one success and one ConflictException, never two silent
    successes -- AWS Backup serializes framework deployment updates.
    """
    backup = ctx.client("backup")

    framework_name = ctx.unique_name("sim2real_behav_framework_")
    backup.create_framework(
        FrameworkName=framework_name,
        FrameworkControls=[{"ControlName": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: backup.delete_framework(FrameworkName=framework_name)))

    # DeploymentStatus reaching COMPLETED requires AWS Config resource recording enabled
    # account-wide, an account-level prerequisite outside this check's control -- so we
    # only wait for the deployment to leave the transient CREATE_IN_PROGRESS state (either
    # COMPLETED or FAILED is a valid terminal state to race the updates against).
    _wait_until(
        lambda: backup.describe_framework(FrameworkName=framework_name)["DeploymentStatus"],
        lambda status: status in ("COMPLETED", "FAILED"),
        timeout_s=120,
    )

    def _update(description: str):
        return backup.update_framework(
            FrameworkName=framework_name,
            FrameworkDescription=description,
            FrameworkControls=[{"ControlName": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"}],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_call_capture, lambda: _update("sim2real-racer-a")),
            pool.submit(_call_capture, lambda: _update("sim2real-racer-b")),
        ]
        results = [f.result() for f in futures]

    codes = [code for _, code in results]
    successes = [result for result, code in results if code is None]

    assert successes, "neither concurrent UpdateFramework call succeeded"
    assert len(successes) == 1, "both concurrent UpdateFramework calls succeeded; expected a serialized conflict"
    assert codes.count("ConflictException") == 1, f"expected exactly one ConflictException, got codes={codes}"

    # effect: the framework settles back to a stable, terminal deployment state (not stuck
    # in a transient CREATE_IN_PROGRESS/UPDATE_IN_PROGRESS state)
    _wait_until(
        lambda: backup.describe_framework(FrameworkName=framework_name)["DeploymentStatus"],
        lambda status: status in ("COMPLETED", "FAILED"),
        timeout_s=120,
    )

    # terminal read, independent of the racing calls' own responses: the stored
    # description reflects exactly one of the two submitted values, never a
    # blend, a blank, or a third value -- the race resolved to a real winner.
    final_description = backup.describe_framework(FrameworkName=framework_name)["FrameworkDescription"]
    assert final_description in ("sim2real-racer-a", "sim2real-racer-b"), (
        f"final FrameworkDescription {final_description!r} does not match either "
        "racing update -- state may be corrupted by the concurrent write"
    )


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _call_capture(fn: Callable[[], Any]) -> tuple[Any, str | None]:
    from botocore.exceptions import ClientError

    try:
        return fn(), None
    except ClientError as err:
        return None, err.response["Error"]["Code"]


def _wait_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
