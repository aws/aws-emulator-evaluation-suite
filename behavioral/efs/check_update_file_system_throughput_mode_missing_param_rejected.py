"""update-file-system-throughput-mode-missing-param-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-file-system-throughput-mode-missing-param-rejected"
GROUP = "overly-permissive"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Switching ThroughputMode to 'provisioned' without ProvisionedThroughputInMibps is rejected as BadRequest."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token,
        ThroughputMode="bursting",
        Tags=[{"Key": "Name", "Value": token}, {"Key": "Owner", "Value": "sim2real"}],
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    code, msg = _client_error(lambda: efs.update_file_system(FileSystemId=fs_id, ThroughputMode="provisioned"))
    assert code == "BadRequest", f"expected BadRequest for a provisioned-mode update missing ProvisionedThroughputInMibps, got {code!r}"
    expected_msg = 'Provisioned throughput must be set for file systems that use provisioned throughput mode.'
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # effect absent: the throughput mode is unchanged and the file system is still available
    unchanged = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]
    assert unchanged["ThroughputMode"] == "bursting", f"expected ThroughputMode unchanged at bursting after the rejected update, got {unchanged['ThroughputMode']!r}"
    assert unchanged["LifeCycleState"] == "available", f"expected LifeCycleState unchanged at available after the rejected update, got {unchanged['LifeCycleState']!r}"

    # positive control: supplying the required conditional parameter succeeds
    efs.update_file_system(FileSystemId=fs_id, ThroughputMode="provisioned", ProvisionedThroughputInMibps=1.0)
    final = _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0],
        lambda fs: fs["LifeCycleState"] == "available" and fs["ThroughputMode"] == "provisioned",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final["ThroughputMode"] == "provisioned", f"expected the positive control (with ProvisionedThroughputInMibps set) to settle at ThroughputMode=provisioned, got {final['ThroughputMode']!r}"


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
