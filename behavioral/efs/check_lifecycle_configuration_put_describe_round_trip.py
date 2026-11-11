"""lifecycle-configuration-put-describe-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lifecycle-configuration-put-describe-round-trip"
GROUP = "data-plane"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLifecycleConfiguration persists transition rules that DescribeLifecycleConfiguration echoes back exactly."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(CreationToken=token, Tags=[{"Key": "sim2real", "Value": CHECK}])["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    initial = efs.describe_lifecycle_configuration(FileSystemId=fs_id)["LifecyclePolicies"]
    assert initial == [], f"expected no lifecycle policies on a fresh file system, got {initial!r}"

    policies = [
        {"TransitionToIA": "AFTER_30_DAYS"},
        {"TransitionToPrimaryStorageClass": "AFTER_1_ACCESS"},
    ]
    put_resp = efs.put_lifecycle_configuration(FileSystemId=fs_id, LifecyclePolicies=policies)
    assert put_resp["LifecyclePolicies"] == policies, (
        f"PutLifecycleConfiguration response expected {policies!r}, got {put_resp['LifecyclePolicies']!r}"
    )

    described = efs.describe_lifecycle_configuration(FileSystemId=fs_id)["LifecyclePolicies"]
    assert described == policies, (
        f"DescribeLifecycleConfiguration expected the persisted policies {policies!r}, got {described!r}"
    )

    cleared = efs.put_lifecycle_configuration(FileSystemId=fs_id, LifecyclePolicies=[])["LifecyclePolicies"]
    assert cleared == [], f"expected PutLifecycleConfiguration([]) to clear policies, got {cleared!r}"
    final = efs.describe_lifecycle_configuration(FileSystemId=fs_id)["LifecyclePolicies"]
    assert final == [], f"expected DescribeLifecycleConfiguration to reflect the clear, got {final!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
