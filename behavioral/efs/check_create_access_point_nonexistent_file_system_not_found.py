"""create-access-point-nonexistent-file-system-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-access-point-nonexistent-file-system-not-found"
GROUP = "error-semantics"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAccessPoint against a FileSystemId that does not exist fails with FileSystemNotFound."""
    efs = ctx.client("efs")
    bogus_fs_id = "fs-00000000"

    try:
        efs.create_access_point(ClientToken=ctx.unique_name("sim2real-efs-ap-"), FileSystemId=bogus_fs_id)
        raise AssertionError("expected FileSystemNotFound for a nonexistent FileSystemId")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "FileSystemNotFound", f"expected FileSystemNotFound, got {code}"
        msg = e.response["Error"].get("Message")
        expected_msg = f"File system '{bogus_fs_id}' does not exist."
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # positive control: a real file system succeeds
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id)

    ap_id = efs.create_access_point(
        ClientToken=ctx.unique_name("sim2real-efs-ap-"),
        FileSystemId=fs_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AccessPointId"]
    ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, ap_id))
    observed_fs_id = efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0]["FileSystemId"]
    assert observed_fs_id == fs_id, f"expected access point bound to {fs_id}, got {observed_fs_id}"


def _wait_fs_state(efs, fs_id, state="available", timeout_s=180.0):
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cur = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"]
        if cur == state:
            return
        time.sleep(5.0)
    raise AssertionError(f"file system {fs_id} never reached {state} within {timeout_s}s")


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
