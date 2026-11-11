"""concurrent-create-deployment-same-target-conflict-tolerant."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-deployment-same-target-conflict-tolerant"
GROUP = "concurrency"
SERVICES = ["greengrassv2"]
_CONFLICT_MESSAGE = (
    "This request conflicts with another operation and can't be completed. Try again in a few seconds."
)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five concurrent CreateDeployment calls for one target: each creates a distinct deployment or
    is refused with ConflictException, and the target then has exactly one latest deployment,
    which is one of the created ones."""
    iot = ctx.client("iot")
    gg = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-gg-race-target-")
    thing = iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    target_arn = thing["thingArn"]

    n = 5

    def create():
        try:
            return gg.create_deployment(targetArn=target_arn)["deploymentId"], None
        except ClientError as exc:
            return None, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    ids = []
    refusals = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(create) for _ in range(n)]
        for future in as_completed(futures):
            deployment_id, refusal = future.result()
            if refusal is None:
                ids.append(deployment_id)
            else:
                refusals.append(refusal)

    for deployment_id in ids:
        ctx.on_cleanup(lambda d=deployment_id: _safe_delete_deployment(ctx, d))

    for code, message in refusals:
        assert code == "ConflictException", f"undocumented CreateDeployment refusal: {code!r} ({message!r})"
        if message != _CONFLICT_MESSAGE:
            in_progress = (
                f"The targetArn '{target_arn}' is already in progress. "
                f"The current operation will be canceled,"
            )
            assert message == in_progress, (
                f"ConflictException message {message!r}, expected {in_progress!r} or "
                f"{_CONFLICT_MESSAGE!r}"
            )
    assert ids, f"every concurrent CreateDeployment was refused: {refusals}"
    assert len(set(ids)) == len(ids), "racers were not all assigned distinct deployment IDs"

    def latest_ids():
        return {
            d["deploymentId"]
            for d in gg.list_deployments(targetArn=target_arn, historyFilter="LATEST_ONLY")[
                "deployments"
            ]
        }

    final_latest = _poll_until(latest_ids, lambda s: len(s) == 1, timeout_s=_wait_s(ctx, 60.0), interval_s=3.0)
    assert final_latest.issubset(set(ids)), f"latest {final_latest} is not one of the racers {ids}"


# ===== helpers =====
def _safe_delete_deployment(ctx, deployment_id: str) -> None:
    gg = ctx.client("greengrassv2")
    deadline = time.monotonic() + 8.0
    try:
        gg.cancel_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        # A deployment that is not ACTIVE cannot be canceled; DeleteDeployment decides.
        if code not in ("ConflictException", "ValidationException"):
            raise
    while True:
        try:
            gg.delete_deployment(deploymentId=deployment_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # DeleteDeployment refuses ("must be canceled before deletion") until the cancel
            # has taken effect; retry only that refusal.
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
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
