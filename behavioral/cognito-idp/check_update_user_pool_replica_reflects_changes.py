"""update-user-pool-replica-reflects-changes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-replica-reflects-changes"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new user pool replica lists as INACTIVE, and UpdateUserPoolReplica moves it to ACTIVE and back to
    INACTIVE, each status read from ListUserPoolReplicas."""
    idp = ctx.client("cognito-idp")
    kms = ctx.client("kms")

    # Just needs to differ from ctx.region -- no resource is pinned to either literal.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    kms_replica = ctx.client("kms", region=replica_region)

    # Real AWS rejects CreateUserPoolReplica with InvalidParameterException unless the pool
    # already carries a customer-managed, multi-Region KMS key with a replica key present in the
    # destination region; this is not documented anywhere the SDK surfaces before
    # the call. Provisioned in-check rather than assumed pre-attached. A default key
    # policy grants the account root IAM-level access but not the AWS *service* principals that
    # back multi-Region user pools: CreateUserPool rejects first for
    # cognito-idp.amazonaws.com, then for identitystore.amazonaws.com (the service multi-Region
    # replication is actually built on) -- both need the resource policy to grant them directly.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    key_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowCognitoUse",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["cognito-idp.amazonaws.com", "identitystore.amazonaws.com"]
                    },
                    "Action": [
                        "kms:CreateGrant",
                        "kms:Decrypt",
                        "kms:DescribeKey",
                        "kms:Encrypt",
                        "kms:GenerateDataKey",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:ReEncryptFrom",
                        "kms:ReEncryptTo",
                    ],
                    "Resource": "*",
                },
            ],
        }
    )
    key_arn = kms.create_key(
        Description="sim2real CMK for multi-Region Cognito user pool replication",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        MultiRegion=True,
        Policy=key_policy,
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    # ReplicateKey is called against the PRIMARY key's own regional endpoint, not the
    # destination's (calling it via the replica-region client raises
    # NotFoundException("Invalid arn us-west-2"), botocore treating ReplicaRegion as unparsable).
    replica_key_arn = kms.replicate_key(
        KeyId=key_arn, ReplicaRegion=replica_region, Policy=key_policy
    )["ReplicaKeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: kms_replica.schedule_key_deletion(KeyId=replica_key_arn, PendingWindowInDays=7)
    )
    _wait_kms_key_enabled(kms_replica, replica_key_arn, timeout_s=120)

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTier="PLUS",
        KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _teardown_pool(idp, pool_id))

    idp.create_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)

    # Cross-region replica provisioning is genuinely slow on real AWS (a replica can still be
    # CREATING past 600s) -- bounded by a stated deadline and a message, never an unconditional
    # sleep, but generous because the alternative is grading a correct target as having hung.
    initial_status = _wait_replica(
        ctx, pool_id, replica_region, lambda s: s != "CREATING", "leave CREATING", timeout_s=1500
    )
    assert initial_status == "INACTIVE", (
        f"expected a freshly created replica to land INACTIVE (administrator-only) before any "
        f"UpdateUserPoolReplica call, got {initial_status!r}"
    )

    idp.update_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region, Status="ACTIVE")
    active_status = _wait_replica(
        ctx, pool_id, replica_region, lambda s: s == "ACTIVE", "reach status 'ACTIVE'", timeout_s=180
    )
    assert active_status == "ACTIVE", (
        f"expected UpdateUserPoolReplica(Status=ACTIVE) to be reflected on a subsequent "
        f"ListUserPoolReplicas read, got {active_status!r}"
    )

    idp.update_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region, Status="INACTIVE")
    final_status = _wait_replica(
        ctx, pool_id, replica_region, lambda s: s == "INACTIVE", "reach status 'INACTIVE'", timeout_s=180
    )
    assert final_status == "INACTIVE", (
        f"expected UpdateUserPoolReplica(Status=INACTIVE) to be reflected on a subsequent "
        f"ListUserPoolReplicas read, got {final_status!r}"
    )


def _wait_kms_key_enabled(kms_client, key_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        last_state = kms_client.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
        if last_state == "Enabled":
            return
        time.sleep(3)
    raise AssertionError(
        f"KMS replica key {key_arn} never reached state Enabled (last seen: {last_state!r})"
    )


def _wait_replica(ctx, pool_id: str, region: str, predicate, description: str, timeout_s: float) -> str:
    idp = ctx.client("cognito-idp")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        replicas = idp.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
        matches = [r for r in replicas if r["RegionName"] == region]
        if matches:
            last_status = matches[0]["Status"]
            if predicate(last_status):
                return last_status
        time.sleep(5)
    raise AssertionError(
        f"replica in {region} never did {description!r} (last seen: {last_status!r})"
    )


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
