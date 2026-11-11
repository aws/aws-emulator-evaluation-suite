"""create-access-point-token-reuse-mismatched-params-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-access-point-token-reuse-mismatched-params-rejected"
GROUP = "idempotency"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-using a ClientToken with a different RootDirectory is rejected, leaving the original AP untouched."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    ap_token = ctx.unique_name("sim2real-efs-ap-")
    original = efs.create_access_point(
        ClientToken=ap_token,
        FileSystemId=fs_id,
        RootDirectory={"Path": "/original-path"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ap_id = original["AccessPointId"]
    ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, ap_id))

    try:
        efs.create_access_point(
            ClientToken=ap_token, FileSystemId=fs_id, RootDirectory={"Path": "/different-path"}
        )
        raise AssertionError("expected AccessPointAlreadyExists on ClientToken/parameter mismatch")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "AccessPointAlreadyExists", (
            f"expected AccessPointAlreadyExists, got {e.response['Error']['Code']!r}"
        )
        msg = e.response["Error"].get("Message")
        expected_msg = None  # AWS sends this error with no Message member
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # the effect is absent: the original access point's root directory did not change
    unchanged = efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0]
    assert unchanged["RootDirectory"]["Path"] == "/original-path", (
        f"expected unchanged root directory /original-path, got {unchanged['RootDirectory']['Path']!r}"
    )

    # positive control: a fresh token with the new params succeeds
    other_token = ctx.unique_name("sim2real-efs-ap-other-")
    other = efs.create_access_point(
        ClientToken=other_token,
        FileSystemId=fs_id,
        RootDirectory={"Path": "/different-path"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    other_id = other["AccessPointId"]
    ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, other_id))
    assert other_id != ap_id, f"expected a distinct access point id, got {other_id!r} == {ap_id!r}"

    # terminal assertion is an independent read, not the mutating call's own response
    seen = efs.describe_access_points(AccessPointId=other_id)["AccessPoints"][0]
    assert seen["RootDirectory"]["Path"] == "/different-path", (
        f"expected the fresh-token access point to read back /different-path, got {seen['RootDirectory']['Path']!r}"
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
