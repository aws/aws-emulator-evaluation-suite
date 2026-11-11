"""update-user-pool-replica-concurrent-modification-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-replica-concurrent-modification-race"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateUserPoolReplica calls flipping a replica between ACTIVE and INACTIVE both
    succeed and settle on one of the two values, consistent across immediate repeated
    ListUserPoolReplicas reads."""
    cognito = ctx.client("cognito-idp")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    secondary_region = _secondary_region(ctx.region)
    account_id = sts.get_caller_identity()["Account"]

    # A multi-Region CMK's DEFAULT key policy grants access only to the account's IAM
    # principals; CreateUserPool with KeyType=CUSTOMER_MANAGED_KEY additionally needs the
    # Cognito service itself to call kms:DescribeKey (and friends) on the key, which requires
    # an explicit resource-policy statement; with the default policy AWS returns
    # InvalidParameterException: "Cognito is not authorized to perform: kms:DescribeKey".
    key_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "sim2real-cognito-replica-race-cmk-policy",
            "Statement": [
                {
                    "Sid": "EnableRootPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    # Essentials/Plus-tier pools store identity data in IdentityStore, which
                    # also needs key access or CreateUserPool fails with
                    # "identitystore.amazonaws.com is not able to access the customer managed key".
                    "Sid": "AllowCognitoServiceAccess",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["cognito-idp.amazonaws.com", "identitystore.amazonaws.com"]
                    },
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKeyWithoutPlainText",
                        "kms:DescribeKey",
                    ],
                    "Resource": "*",
                },
            ],
        }
    )

    try:
        key_metadata = kms.create_key(
            MultiRegion=True,
            Description="sim2real cognito-idp replica behavioral check",
            Policy=key_policy,
            Tags=[{"TagKey": "sim2real", "TagValue": "cognito-idp-replica-race"}],
        )["KeyMetadata"]
    except ClientError as exc:
        raise AssertionError(
            f"cannot create a multi-Region KMS key in this account/region: {exc.response['Error']['Code']}: {exc.response['Error'].get('Message')}"
        )
    key_id = key_metadata["KeyId"]
    key_arn = key_metadata["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    try:
        kms.replicate_key(KeyId=key_id, ReplicaRegion=secondary_region, Policy=key_policy)
    except ClientError as exc:
        raise AssertionError(
            f"cannot replicate the KMS key into {secondary_region}: {exc.response['Error']['Code']}: {exc.response['Error'].get('Message')}"
        )
    # A multi-Region replica key is an independent KMS resource in its own region -- deleting
    # the primary does not delete it, so it needs its own scheduled-deletion cleanup.
    replica_kms = ctx.client("kms", region=secondary_region)
    ctx.on_cleanup(lambda: replica_kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    try:
        pool = cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-mrr-pool-"),
            UserPoolTier="PLUS",
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mrr-pool"},
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
        )["UserPool"]
    except ClientError as exc:
        raise AssertionError(
            "cannot create a Plus-tier pool with a customer-managed KMS key: "
            f"{exc.response['Error']['Code']}: {exc.response['Error'].get('Message')}"
        )
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: _teardown_pool(cognito, pool_id))

    # The replica KMS key can take an undocumented window to become usable cross-Region;
    # poll the only observable signal available (CreateUserPoolReplica itself succeeding)
    # rather than sleeping a fixed duration.
    def _try_create_replica():
        try:
            cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=secondary_region)
            return True, None
        except ClientError as exc:
            return False, exc.response["Error"]["Code"]

    created, last_code = _poll_until(
        _try_create_replica, lambda result: result[0], timeout_s=120.0, interval_s=5.0
    )
    if not created:
        raise AssertionError(
            f"CreateUserPoolReplica did not succeed within the polling window in "
            f"{secondary_region}: {last_code}"
        )

    _wait_replica_ready(cognito, pool_id, secondary_region, timeout_s=780.0)

    def _flip(status):
        return cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=secondary_region, Status=status
        )

    # A sequential update is applied, so the race below starts from a state a dropped write
    # cannot fake.
    _flip("INACTIVE")
    settled = _poll_until(
        lambda: _find_replica(cognito, pool_id, secondary_region),
        lambda r: r is not None and r["Status"] == "INACTIVE",
        timeout_s=max(1.0, min(120.0, (ctx.time_left() or 120.0) - 30.0)),
        interval_s=5.0,
    )
    assert settled is not None and settled["Status"] == "INACTIVE", (
        f"UpdateUserPoolReplica(INACTIVE) did not apply: {settled!r}"
    )

    with ThreadPoolExecutor(max_workers=2) as pool_exec:
        fut_active = pool_exec.submit(_flip, "ACTIVE")
        fut_inactive = pool_exec.submit(_flip, "INACTIVE")
        # UpdateUserPoolReplica declares no conflict error, so both racers should succeed.
        fut_active.result()
        fut_inactive.result()

    read_a = _find_replica(cognito, pool_id, secondary_region)
    read_b = _find_replica(cognito, pool_id, secondary_region)
    assert read_a is not None and read_b is not None, "replica disappeared after the race"
    assert read_a["Status"] == read_b["Status"], "replica status flapped across immediate re-reads"
    assert read_a["Status"] in ("ACTIVE", "INACTIVE"), f"replica stuck in {read_a['Status']!r}"



def _secondary_region(primary_region: str) -> str:
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _find_replica(cognito, pool_id, region_name):
    replicas = cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
    for replica in replicas:
        if replica["RegionName"] == region_name:
            return replica
    return None


def _wait_replica_ready(cognito, pool_id, region_name, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        replica = _find_replica(cognito, pool_id, region_name)
        if replica is not None and replica["Status"] != "CREATING":
            return
        time.sleep(2)
    raise AssertionError("replica never left the CREATING state")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _teardown_pool(cognito, pool_id, timeout_s: float = 1200.0, interval_s: float = 15.0):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
