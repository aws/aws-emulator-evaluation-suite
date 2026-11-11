"""user-pool-replica-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-pool-replica-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_CREATE_S = 1500.0
_AFTER_CREATE_S = 300.0
_CLEANUP_S = 1800.0  # the suite's cleanup budget, shared by the check's teardowns
_CLEANUP_HEADROOM_S = 120.0
_REPLICA_BUSY = "Replica cannot be deleted while in "
_REPLICAS_LEFT = (
    "Cannot delete user pool that has secondary replicas. "
    "Please delete all replicas before deleting the user pool."
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replica of a pool with a multi-Region key lists and settles INACTIVE, moves to ACTIVE and back as
    ListUserPoolReplicas reads, and once deleted is unlisted and UpdateUserPoolReplica on it fails with
    ResourceNotFoundException and its exact message."""
    cognito = ctx.client("cognito-idp")
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    key_arn = _create_multiregion_cmk(ctx, replica_region)

    try:
        pool_id = cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-pool-"),
            UserPoolTier="PLUS",
            DeletionProtection="INACTIVE",
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
            UserPoolTags={"sim2real": "cognito-idp-replica-lifecycle-check"},
        )["UserPool"]["Id"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "FeatureUnavailableInTierException":
            raise AssertionError("account/region doesn't support the Plus feature tier required for replication")
        raise
    cleanup_deadline: dict = {}
    ctx.on_cleanup(lambda: _delete_pool(cognito, pool_id, cleanup_deadline))

    try:
        cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "FeatureUnavailableInTierException":
            raise AssertionError("user pool replication not available for this account/region")
        raise
    ctx.on_cleanup(lambda: _delete_replica(cognito, pool_id, replica_region, cleanup_deadline))

    replicas = cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
    regions = {r["RegionName"] for r in replicas}
    assert replica_region in regions, replicas

    # UpdateUserPoolReplica rejects a replica still in CREATING, so provisioning must finish
    # first; real AWS can take well over 800 s, so the poll takes the budget the later legs leave.
    left = ctx.time_left()
    create_s = _CREATE_S if left is None else max(0.0, min(_CREATE_S, left - _AFTER_CREATE_S))
    status = _wait_replica_status(
        cognito, pool_id, replica_region, lambda s: s != "CREATING", timeout_s=create_s, interval_s=2.0, no_raise=True
    )
    if status == "CREATING":
        raise AssertionError(
            f"replica in {replica_region} never left CREATING within {create_s:.0f}s -- multi-Region user "
            "pool replication cannot be exercised end-to-end on this account"
        )
    # A freshly created replica settles INACTIVE; ACTIVE is reached only through
    # UpdateUserPoolReplica, which the leg below exercises.
    assert status == "INACTIVE", (
        f"expected a freshly created replica to settle INACTIVE, got {status!r}"
    )

    # ACTIVE is reached only by asking for it -- the transition this check exists to exercise.
    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region, Status="ACTIVE")
    status_active = _wait_replica_status(
        cognito, pool_id, replica_region, lambda s: s == "ACTIVE", timeout_s=120.0, interval_s=5.0
    )
    assert status_active == "ACTIVE", (
        f"UpdateUserPoolReplica(Status=ACTIVE) was not reflected on an independent "
        f"ListUserPoolReplicas read, got {status_active!r}"
    )

    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region, Status="INACTIVE")
    status_after_update = _wait_replica_status(
        cognito, pool_id, replica_region, lambda s: s == "INACTIVE", timeout_s=120.0, interval_s=5.0
    )
    assert status_after_update == "INACTIVE"

    cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
    # A deleted replica stays listed as DELETING for minutes; poll every 2 s, capped by the run budget.
    left = ctx.time_left()
    gone_deadline = time.monotonic() + (600.0 if left is None else max(0.0, min(600.0, left - 30.0)))
    while True:
        replicas_final = cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
        regions_final = {r["RegionName"] for r in replicas_final}
        if replica_region not in regions_final or time.monotonic() >= gone_deadline:
            break
        time.sleep(2)
    assert replica_region not in regions_final, (
        f"replica {replica_region} still listed after DeleteUserPoolReplica: {replicas_final!r}"
    )

    # A mutation on the now-gone replica must fail the same way a mutation on one that never
    # existed does -- deleting it did not merely hide it from the list.
    dead_code, dead_message = _error(
        lambda: cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=replica_region, Status="ACTIVE"
        )
    )
    assert dead_code == "ResourceNotFoundException", dead_code
    assert dead_message == "Replica not found in the requested region", dead_message


def _delete_replica(cognito, pool_id, region_name, cleanup_deadline: dict) -> None:
    """Deactivate, then delete the replica and wait until it is gone; only INACTIVE deletes."""
    deadline = cleanup_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - _CLEANUP_HEADROOM_S)
    while True:
        try:
            status = _replica_status(cognito, pool_id, region_name)
            if status is None:
                return
            if status == "ACTIVE":
                cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=region_name, Status="INACTIVE")
            elif status == "INACTIVE":
                cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=region_name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            busy = code == "InvalidParameterException" and exc.response["Error"].get("Message", "").startswith(
                _REPLICA_BUSY
            )
            if not busy or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"replica {region_name} of {pool_id} not deleted within the cleanup budget")
        time.sleep(2)


def _delete_pool(cognito, pool_id, cleanup_deadline: dict) -> None:
    """Delete the pool; retry while a deleted replica is still attached, return if already gone."""
    deadline = cleanup_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - _CLEANUP_HEADROOM_S)
    while True:
        try:
            cognito.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            refused = (error["Code"], error.get("Message")) == ("InvalidParameterException", _REPLICAS_LEFT)
            if not refused or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error(fn):
    """The (code, message) of the expected refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _replica_status(cognito, pool_id, region_name):
    for r in cognito.list_user_pool_replicas(UserPoolId=pool_id).get("UserPoolReplicas", []):
        if r["RegionName"] == region_name:
            return r["Status"]
    return None


def _wait_replica_status(
    cognito, pool_id, region_name, predicate, timeout_s: float = 240.0, interval_s: float = 10.0, no_raise: bool = False
):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _replica_status(cognito, pool_id, region_name)
        if predicate(status):
            return status
        time.sleep(interval_s)
    if no_raise:
        return status
    raise AssertionError(f"replica in {region_name} status never satisfied condition within {timeout_s}s, last={status!r}")


def _create_multiregion_cmk(ctx, replica_region):
    # Real AWS rejects CreateUserPoolReplica for a syntactically valid region with
    # InvalidParameterException ("User pool needs a customer-managed KMS key for multi-region
    # replication") unless the pool's own key is a multi-Region CMK with grants for the services
    # that back replication -- so that CMK is a real in-check prerequisite, not an external one.
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableIamUserPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCognitoUserPoolReplication",
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
                "Action": [
                    "kms:DescribeKey",
                    "kms:CreateGrant",
                    "kms:Decrypt",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKeyWithoutPlaintext",
                    "kms:ReEncryptFrom",
                    "kms:ReEncryptTo",
                ],
                "Resource": "*",
            },
            {
                # The multi-Region user pool's directory storage is backed by AWS's identity
                # store infrastructure behind the scenes; real AWS names it explicitly in its
                # own error message when this grant is missing.
                "Sid": "AllowIdentityStoreUserPoolReplication",
                "Effect": "Allow",
                "Principal": {"Service": "identitystore.amazonaws.com"},
                "Action": [
                    "kms:DescribeKey",
                    "kms:Decrypt",
                    "kms:Encrypt",
                    "kms:GenerateDataKeyWithoutPlaintext",
                    "kms:ReEncryptFrom",
                    "kms:ReEncryptTo",
                ],
                "Resource": "*",
            },
        ],
    }
    key_id = kms.create_key(
        MultiRegion=True,
        Policy=json.dumps(key_policy),
        Description="sim2real cognito-idp user-pool-replica-lifecycle CMK",
        Tags=[{"TagKey": "sim2real", "TagValue": "cognito-idp-replica-lifecycle-check"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # A multi-Region primary key has no cryptographic material outside its own region until a
    # replica key is minted in the target region -- CreateUserPoolReplica needs that replica key
    # to exist, not just the primary.
    kms.replicate_key(KeyId=key_id, ReplicaRegion=replica_region, Policy=json.dumps(key_policy))
    kms_replica_region = ctx.client("kms", region=replica_region)
    ctx.on_cleanup(
        lambda: kms_replica_region.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    _wait_key_enabled(kms_replica_region, key_id)
    return kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]


def _wait_key_enabled(kms_client, key_id, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if state == "Enabled":
            return
        time.sleep(interval_s)
    raise AssertionError(f"KMS replica key {key_id} never reached Enabled within {timeout_s}s, last state={state!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
