"""create-access-point-lifecycle-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-access-point-lifecycle-transition"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAccessPoint moves an access point through creating -> available."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "sim2real", "Value": token}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    ap_token = ctx.unique_name("sim2real-efs-ap-")
    created = efs.create_access_point(
        ClientToken=ap_token,
        FileSystemId=fs_id,
        RootDirectory={
            "Path": "/sim2real-test",
            "CreationInfo": {"OwnerUid": 1000, "OwnerGid": 1000, "Permissions": "0755"},
        },
        Tags=[{"Key": "sim2real", "Value": ap_token}],
    )
    ap_id = created["AccessPointId"]
    ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, ap_id))

    assert created["LifeCycleState"] in ("creating", "available"), (
        f"expected creating|available right after create, got {created['LifeCycleState']!r}"
    )
    assert created["FileSystemId"] == fs_id, (
        f"expected FileSystemId {fs_id!r}, got {created['FileSystemId']!r}"
    )
    assert created["RootDirectory"]["Path"] == "/sim2real-test", (
        f"expected RootDirectory.Path '/sim2real-test', got {created['RootDirectory']['Path']!r}"
    )
    created_info = created["RootDirectory"]["CreationInfo"]
    assert (created_info["OwnerUid"], created_info["OwnerGid"], created_info["Permissions"]) == (
        1000,
        1000,
        "0755",
    ), f"expected CreationInfo (1000, 1000, '0755'), got {created_info!r}"

    final = _poll_until(
        lambda: efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0],
        lambda ap: ap["LifeCycleState"] == "available",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["LifeCycleState"] == "available", (
        f"expected access point {ap_id} to reach 'available', last seen {final['LifeCycleState']!r}"
    )
    assert final["AccessPointId"] == ap_id, (
        f"expected independent read to return AccessPointId {ap_id!r}, got {final['AccessPointId']!r}"
    )
    assert final["RootDirectory"]["Path"] == "/sim2real-test", (
        f"expected independent read to echo RootDirectory.Path '/sim2real-test', "
        f"got {final['RootDirectory']['Path']!r}"
    )


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


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


def _delete_ap_best_effort(efs, ap_id):
    try:
        efs.delete_access_point(AccessPointId=ap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessPointNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
