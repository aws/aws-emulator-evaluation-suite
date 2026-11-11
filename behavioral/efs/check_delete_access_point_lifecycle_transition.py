"""delete-access-point-lifecycle-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-access-point-lifecycle-transition"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAccessPoint moves an access point through deleting -> deleted (NotFound)."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(CreationToken=token, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "FileSystemId"
    ]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    ap_token = ctx.unique_name("sim2real-efs-ap-")
    ap_id = efs.create_access_point(
        ClientToken=ap_token, FileSystemId=fs_id, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["AccessPointId"]
    _wait_ap_state(efs, ap_id, "available")

    efs.delete_access_point(AccessPointId=ap_id)

    _wait_ap_deleted(efs, ap_id)
    code, msg = _client_error(lambda: efs.describe_access_points(AccessPointId=ap_id))
    assert code == "AccessPointNotFound", f"expected AccessPointNotFound after delete, got {code!r}"
    expected_msg = f"Access point '{ap_id}' does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


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


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
