"""delete-access-point-concurrent-delete-idempotent."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-access-point-concurrent-delete-idempotent"
GROUP = "concurrency"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent DeleteAccessPoint calls on one live access point: at least one is accepted, any
    other gets only AccessPointNotFound with its exact message, and afterwards both a describe and a
    further delete are refused with AccessPointNotFound."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(CreationToken=token)["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available", timeout_s=_bounded(ctx, 180.0, reserve_s=40.0))

    ap_id = efs.create_access_point(ClientToken=ctx.unique_name("sim2real-efs-ap-"), FileSystemId=fs_id)[
        "AccessPointId"
    ]
    ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, ap_id))
    _wait_ap_state(efs, ap_id, "available", timeout_s=_bounded(ctx, 120.0, reserve_s=30.0))

    def attempt(_i):
        try:
            efs.delete_access_point(AccessPointId=ap_id)
            return ("ok", None)
        except ClientError as e:
            return (e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    not_found_msg = f"Access point '{ap_id}' does not exist."
    assert any(code == "ok" for code, _ in results), f"no concurrent delete was accepted: {results}"
    for code, msg in results:
        if code == "ok":
            continue
        assert code == "AccessPointNotFound", f"unexpected error deleting the access point: {results}"
        assert msg == not_found_msg, f"expected message {not_found_msg!r}, got {msg!r}"

    # the access point is actually gone, and stays gone: an independent read agrees,
    # and a further delete of the same id is rejected rather than silently accepted again
    _wait_ap_deleted(efs, ap_id, timeout_s=_bounded(ctx, 120.0, reserve_s=10.0))
    final_code, final_msg = _client_error(lambda: efs.describe_access_points(AccessPointId=ap_id))
    assert final_code == "AccessPointNotFound", f"expected AccessPointNotFound, got {final_code!r}"
    assert final_msg == not_found_msg, f"expected message {not_found_msg!r}, got {final_msg!r}"

    redelete_code, redelete_msg = _client_error(lambda: efs.delete_access_point(AccessPointId=ap_id))
    assert redelete_code == "AccessPointNotFound", f"expected AccessPointNotFound, got {redelete_code!r}"
    assert redelete_msg == not_found_msg, f"expected message {not_found_msg!r}, got {redelete_msg!r}"


def _bounded(ctx, wanted_s: float, *, reserve_s: float) -> float:
    """`wanted_s`, cut so `reserve_s` of the check's budget is left for what follows."""
    left = ctx.time_left()
    return wanted_s if left is None else max(1.0, min(wanted_s, left - reserve_s))


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_fs_state(efs, fs_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _wait_ap_state(efs, ap_id, state, timeout_s=120.0):
    return _poll_until(
        lambda: efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=3.0,
    )


def _wait_ap_deleted(efs, ap_id, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            efs.describe_access_points(AccessPointId=ap_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessPointNotFound":
                return
            raise
        time.sleep(3.0)
    raise AssertionError(f"access point {ap_id} not deleted within {timeout_s}s")


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_ap_best_effort(efs, ap_id):
    try:
        efs.delete_access_point(AccessPointId=ap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessPointNotFound":
            raise


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
