"""update-user-pool-replica-concurrent-updates-serialized."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-replica-concurrent-updates-serialized"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent ACTIVE and INACTIVE UpdateUserPoolReplica calls on one replica are serialized:
    each response echoes its request and the replica settles stably on one of the two statuses.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-multi-region.html
    """
    cognito = ctx.client("cognito-idp")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    # Replication needs a second region distinct from ctx.region.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    kms_replica = ctx.client("kms", region=replica_region)
    account_id = sts.get_caller_identity()["Account"]

    # A customer-managed key used as a user pool's KeyConfiguration is only usable if its
    # key policy grants two service principals DescribeKey/Encrypt/Decrypt -- the default
    # policy (Policy omitted) grants neither, and CreateUserPool then fails with
    # InvalidParameterException naming whichever principal it checks first:
    # cognito-idp.amazonaws.com, then identitystore.amazonaws.com (an
    # Essentials/Plus-tier pool backs onto IAM Identity Center's identity store). Passing a
    # custom Policy replaces the default entirely, so root permissions must be granted
    # explicitly or the key becomes unmanageable.
    _kms_actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKeyWithoutPlainText",
        "kms:DescribeKey",
    ]
    key_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "sim2real-cognito-replica-cmk-policy",
            "Statement": [
                {
                    "Sid": "EnableRootPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowCognitoServiceAccess",
                    "Effect": "Allow",
                    "Principal": {"Service": "cognito-idp.amazonaws.com"},
                    "Action": _kms_actions,
                    "Resource": "*",
                },
                {
                    "Sid": "AllowIdentityStoreServiceAccess",
                    "Effect": "Allow",
                    "Principal": {"Service": "identitystore.amazonaws.com"},
                    "Action": _kms_actions,
                    "Resource": "*",
                },
            ],
        }
    )

    try:
        key_id = kms.create_key(
            MultiRegion=True,
            Description="sim2real cognito-idp replica test key",
            Policy=key_policy,
            Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
        )["KeyMetadata"]["KeyId"]
    except ClientError as exc:
        raise AssertionError(
            f"could not create a multi-Region KMS key in this account: "
            f"{exc.response['Error']['Code']}"
        )
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    try:
        kms.replicate_key(
            KeyId=key_id,
            ReplicaRegion=replica_region,
            Policy=key_policy,
            Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
        )
    except ClientError as exc:
        raise AssertionError(
            f"could not replicate the multi-Region KMS key into {replica_region}: "
            f"{exc.response['Error']['Code']}"
        )
    ctx.on_cleanup(lambda: _delete_replica_key(kms_replica, key_id))

    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    try:
        pool_id = cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-replica-"),
            UserPoolTier="ESSENTIALS",
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["UserPool"]["Id"]
    except ClientError as exc:
        raise AssertionError(
            f"could not create an Essentials-tier user pool with a customer managed "
            f"KMS key in this account: {exc.response['Error']['Code']}: "
            f"{exc.response['Error'].get('Message')}"
        )
    ctx.on_cleanup(lambda: _teardown_pool(cognito, pool_id))

    def try_create_replica():
        try:
            cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
            return True, None
        except ClientError as exc:
            return False, exc.response["Error"]["Code"]

    # The replica KMS key can take a short, undocumented window to become usable
    # cross-Region; poll the only observable signal there is: CreateUserPoolReplica
    # itself succeeding.
    created, last_code = _poll_until(
        try_create_replica, lambda result: result[0], timeout_s=_budget_s(ctx, 120), interval_s=2
    )
    if not created and _budget_spent(ctx):
        raise TimeoutError("CreateUserPoolReplica succeeding: the run budget ended first; not graded")
    if not created:
        raise AssertionError(
            f"CreateUserPoolReplica did not succeed within the polling window in this "
            f"account/Region: {last_code}"
        )

    # Wait for the replica to leave the transient CREATING state before racing updates --
    # UpdateUserPoolReplica rejects a still-CREATING replica with InvalidParameterException.
    # Replica creation can take several minutes, hence the 600s bound.
    settle_status = _poll_until(
        lambda: _replica_status(cognito, pool_id, replica_region),
        lambda status: status in ("ACTIVE", "INACTIVE"),
        timeout_s=_budget_s(ctx, 600),
        interval_s=2,
    )
    if settle_status not in ("ACTIVE", "INACTIVE") and _budget_spent(ctx):
        raise TimeoutError("replica leaving the CREATING state: the run budget ended first; not graded")
    if settle_status not in ("ACTIVE", "INACTIVE"):
        raise AssertionError(
            f"replica did not leave the CREATING state within the polling window: "
            f"last saw {settle_status!r}"
        )

    def set_active():
        return cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=replica_region, Status="ACTIVE"
        )

    def set_inactive():
        return cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=replica_region, Status="INACTIVE"
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_active = pool.submit(set_active)
        fut_inactive = pool.submit(set_inactive)
        result_active = fut_active.result()
        result_inactive = fut_inactive.result()

    assert result_active["UserPoolReplica"]["Status"] == "ACTIVE", (
        f"the ACTIVE request's own response must echo ACTIVE, got "
        f"{result_active['UserPoolReplica']['Status']!r}"
    )
    assert result_inactive["UserPoolReplica"]["Status"] == "INACTIVE", (
        f"the INACTIVE request's own response must echo INACTIVE, got "
        f"{result_inactive['UserPoolReplica']['Status']!r}"
    )

    final_status = _replica_status(cognito, pool_id, replica_region)
    assert final_status in ("ACTIVE", "INACTIVE"), (
        f"replica settled in an unexpected status {final_status!r} after the race"
    )

    # Stability: repeated reads must keep reporting the exact same settled status --
    # no flapping between the two racing writes, no corrupted third state.
    for _ in range(3):
        time.sleep(1)
        reread = _replica_status(cognito, pool_id, replica_region)
        assert reread == final_status, (
            f"replica status flapped after settling: was {final_status!r}, reread {reread!r}"
        )


def _replica_status(cognito, pool_id: str, replica_region: str) -> str:
    replicas = cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
    for replica in replicas:
        if replica["RegionName"] == replica_region:
            return replica["Status"]
    raise AssertionError(f"no replica found for Region {replica_region}")


def _delete_replica_key(kms_replica, key_id: str) -> None:
    kms_replica.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown_pool(cognito, pool_id, timeout_s: float = 1200.0, interval_s: float = 2.0):
    """Delete every secondary replica, then the pool. DeleteUserPoolReplica refuses a replica
    in CREATING or ACTIVE status, so an ACTIVE replica is set INACTIVE first; replica deletion is
    asynchronous, and DeleteUserPool refuses a pool that still lists a secondary replica, so each
    step waits for the one before it to settle."""
    deadline = time.monotonic() + timeout_s
    requested = set()
    while True:
        replicas = cognito.list_user_pool_replicas(UserPoolId=pool_id).get("UserPoolReplicas", [])
        secondaries = [r for r in replicas if r.get("Role") != "PRIMARY"]
        if not secondaries:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"secondary replicas of {pool_id} never cleared: {secondaries!r}")
        for replica in secondaries:
            region, status = replica["RegionName"], replica.get("Status")
            if region in requested or status in ("CREATING", "DELETING"):
                continue
            try:
                if status == "ACTIVE":
                    cognito.update_user_pool_replica(
                        UserPoolId=pool_id, RegionName=region, Status="INACTIVE"
                    )
                else:
                    cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=region)
                    requested.add(region)
            except ClientError as err:
                if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
        time.sleep(interval_s)
    cognito.delete_user_pool(UserPoolId=pool_id)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
