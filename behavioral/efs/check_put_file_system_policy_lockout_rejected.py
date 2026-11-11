"""put-file-system-policy-lockout-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-file-system-policy-lockout-rejected"
GROUP = "overly-permissive"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy that would lock the caller out of future PutFileSystemPolicy calls is rejected unless bypassed."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    created = efs.create_file_system(CreationToken=token, Tags=[{"Key": "sim2real", "Value": CHECK}])
    fs_id = created["FileSystemId"]
    fs_arn = created["FileSystemArn"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    lockout_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyFuturePutPolicy",
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "elasticfilesystem:PutFileSystemPolicy",
                    "Resource": fs_arn,
                }
            ],
        }
    )

    code, msg = _client_error(lambda: efs.put_file_system_policy(FileSystemId=fs_id, Policy=lockout_policy))
    assert code == "InvalidPolicyException", (
        f"a policy denying future PutFileSystemPolicy calls should be rejected as "
        f"InvalidPolicyException, got {code!r}"
    )
    expected_msg = 'This policy would prevent future FileSystemPolicy updates. Retry the request with the BypassPolicyLockoutSafetyCheck parameter to apply this policy.'
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # effect absent: no explicit policy was ever persisted for this file system
    describe_code, describe_msg = _client_error(lambda: efs.describe_file_system_policy(FileSystemId=fs_id))
    assert describe_code == "PolicyNotFound", (
        f"the rejected lockout policy must not have been persisted, expected describe to fail "
        f"with PolicyNotFound, got {describe_code!r}"
    )
    expected_describe_msg = None  # AWS sends this error with no Message member
    assert describe_msg == expected_describe_msg, f"expected message {expected_describe_msg!r}, got {describe_msg!r}"

    # positive control: the identical policy succeeds when the safety check is bypassed
    put_resp = efs.put_file_system_policy(
        FileSystemId=fs_id, Policy=lockout_policy, BypassPolicyLockoutSafetyCheck=True
    )
    put_policy = json.loads(put_resp["Policy"])
    expected_policy = json.loads(lockout_policy)
    assert put_policy == expected_policy, (
        f"bypassing the lockout safety check should persist the identical policy, "
        f"expected {expected_policy!r}, got {put_policy!r}"
    )
    described = efs.describe_file_system_policy(FileSystemId=fs_id)
    described_policy = json.loads(described["Policy"])
    assert described_policy == expected_policy, (
        f"an independent describe should read back the identical bypassed policy, "
        f"expected {expected_policy!r}, got {described_policy!r}"
    )

    # the delete this check performs to unblock its own cleanup is itself a free negative:
    # prove the policy is gone via an independent read, not just that the call returned.
    efs.delete_file_system_policy(FileSystemId=fs_id)
    post_delete_code, post_delete_msg = _client_error(lambda: efs.describe_file_system_policy(FileSystemId=fs_id))
    assert post_delete_code == "PolicyNotFound", (
        f"after deleting the file system policy, an independent describe should fail with "
        f"PolicyNotFound, got {post_delete_code!r}"
    )
    expected_post_delete_msg = None  # AWS sends this error with no Message member
    assert post_delete_msg == expected_post_delete_msg, (
        f"expected message {expected_post_delete_msg!r}, got {post_delete_msg!r}"
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
        efs.delete_file_system_policy(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
