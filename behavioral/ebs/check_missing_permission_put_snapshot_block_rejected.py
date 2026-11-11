"""missing-permission-put-snapshot-block-rejected."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-permission-put-snapshot-block-rejected"
GROUP = "overly-permissive"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288
_SESSION_NAME = "sim2real-ebs-deny-test"


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM role with an explicit Deny on ebs:PutSnapshotBlock gets AccessDeniedException; the write does not persist."""
    ebs = ctx.client("ebs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-ebs-deny-role-")
    policy_name = ctx.unique_name("sim2real-ebs-deny-policy-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["ec2:DescribeSnapshots"], "Resource": "*"},
            {"Effect": "Deny", "Action": ["ebs:PutSnapshotBlock"], "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(lambda: _delete_role_policy(ctx, role_name, policy_name))

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = _assume_role_with_retry(sts, role_arn)
    role_creds = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    restricted_ec2 = ctx.client("ec2", creds=role_creds)
    restricted_ebs = ctx.client("ebs", creds=role_creds)
    _wait_until_allowed(restricted_ec2)  # confirm the role/policy is effective before testing the deny

    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    denied_data = os.urandom(_BLOCK_SIZE)
    code, msg = _error_code_msg(lambda: restricted_ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=denied_data, DataLength=len(denied_data),
        Checksum=_sha256_b64(denied_data), ChecksumAlgorithm="SHA256",
    ))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert msg == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: ebs:PutSnapshotBlock on resource: "
        f"arn:aws:ec2:{ctx.region}::snapshot/{snapshot_id} with an explicit deny in an "
        f"identity-based policy"
    ), f"got msg={msg!r}"

    # positive control: the full-permission caller can write to the same snapshot
    control_data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=1, BlockData=control_data, DataLength=len(control_data),
        Checksum=_sha256_b64(control_data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    indices = {b["BlockIndex"] for b in listing["Blocks"]}
    assert indices == {1}, f"the denied write must not have persisted, got {indices}"


# ===== helpers =====
def _assume_role_with_retry(sts, role_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_err}")


def _wait_until_allowed(restricted_ec2, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            restricted_ec2.describe_snapshots(MaxResults=5)
            return
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"restricted role's Allow policy never took effect: {last_err}")


def _error_code_msg(fn):
    """Call fn(); return (Code, Message) from the ClientError it raises. An unexpected SUCCESS
    raises rather than returning a sentinel, so a target that ignores the Deny cannot read as a
    plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be rejected but SUCCEEDED, returning {result!r}")


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _list_blocks_with_retry(ebs, snapshot_id, timeout_s=180.0, interval_s=3.0):
    """The EBS direct-API data plane can lag EC2's completed-state signal briefly; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ebs.list_snapshot_blocks(SnapshotId=snapshot_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"ListSnapshotBlocks never found completed snapshot {snapshot_id}: {last_err}")


def _wait_for_snapshot_state(ctx, snapshot_id, states, timeout_s=120.0, interval_s=3.0):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
            last = resp["Snapshots"][0]["State"]
            if last in states:
                return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_id} never reached {states} (last={last})")


def _delete_snapshot(ctx, snapshot_id):
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


def _delete_role_policy(ctx, role_name, policy_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

