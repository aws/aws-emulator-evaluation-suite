"""update-user-pool-replica-reflects-region-config-change."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-replica-reflects-region-config-change"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolReplica starts INACTIVE; UpdateUserPoolReplica drives it to ACTIVE and back to
    INACTIVE, each state visible on a fresh ListUserPoolReplicas call (no per-replica Describe).
    """
    cognito = ctx.client("cognito-idp")
    sts = ctx.client("sts")
    kms = ctx.client("kms")
    # Replication needs a second Region distinct from ctx.region; pick a fixed partner.
    secondary_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    kms_secondary = ctx.client("kms", region=secondary_region)
    account_id = sts.get_caller_identity()["Account"]

    # CreateUserPoolReplica requires the pool to already be encrypted with a multi-Region
    # customer-managed KMS key present in every Region the pool replicates to -- an
    # AWS_OWNED_KEY-encrypted (the default) pool is rejected with InvalidParameterException.
    # The key policy must also allow identitystore.amazonaws.com: without it CreateUserPool
    # fails with InvalidParameterException naming identitystore, though only cognito-idp is
    # documented.
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
                    "Principal": {
                        "Service": ["cognito-idp.amazonaws.com", "identitystore.amazonaws.com"]
                    },
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:DescribeKey",
                    ],
                    "Resource": "*",
                },
            ],
        }
    )
    key = kms.create_key(
        MultiRegion=True,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description="sim2real-behav-mrr cognito replica CMK (multi-Region primary)",
        Policy=key_policy,
        Tags=[{"TagKey": "Name", "TagValue": ctx.unique_name("sim2real-behav-mrr-cmk-")}],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    kms.replicate_key(KeyId=key_id, ReplicaRegion=secondary_region, Policy=key_policy)
    ctx.on_cleanup(
        lambda: kms_secondary.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    def _replica_key_state():
        try:
            return kms_secondary.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        except ClientError as exc:
            if _error_code(exc) == "NotFoundException":
                return None  # replication still propagating
            raise

    _poll_until(
        _replica_key_state,
        lambda state: state == "Enabled",
        timeout_s=400,
        interval_s=10,
    )

    try:
        pool = cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-mrr-"),
            UserPoolTier="PLUS",
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-mrr"},
        )["UserPool"]
    except ClientError as exc:
        raise AssertionError(
            "cannot create a Plus-tier user pool with a multi-Region CMK (prerequisite for "
            f"multi-Region replication) in this account/region: {_error_code(exc)}: {exc}"
        )
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    try:
        cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=secondary_region)
    except ClientError as exc:
        raise AssertionError(
            "CreateUserPoolReplica was rejected even with a multi-Region CMK attached to the "
            f"pool -- this account/Region pair may lack the required Cognito infrastructure "
            f"eligibility: {_error_code(exc)}: {exc}"
        )
    ctx.on_cleanup(
        lambda: cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=secondary_region)
    )

    def _replica_status() -> str | None:
        resp = cognito.list_user_pool_replicas(UserPoolId=pool_id)
        for replica in resp.get("UserPoolReplicas", []):
            if replica.get("RegionName") == secondary_region:
                return replica.get("Status")
        return None

    # A new replica can sit in CREATING for over 700s; the ACTIVE/INACTIVE flips after it are fast.
    initial_status = _poll_until(_replica_status, lambda s: s in ("INACTIVE", "ACTIVE"), timeout_s=900)
    assert initial_status == "INACTIVE", f"expected new replica to start INACTIVE, got {initial_status}"

    cognito.update_user_pool_replica(
        UserPoolId=pool_id, RegionName=secondary_region, Status="ACTIVE"
    )
    active_status = _poll_until(_replica_status, lambda s: s == "ACTIVE", timeout_s=90)
    assert active_status == "ACTIVE", f"UpdateUserPoolReplica(ACTIVE) not reflected, got {active_status}"

    cognito.update_user_pool_replica(
        UserPoolId=pool_id, RegionName=secondary_region, Status="INACTIVE"
    )
    final_status = _poll_until(_replica_status, lambda s: s == "INACTIVE", timeout_s=90)
    assert final_status == "INACTIVE", f"UpdateUserPoolReplica(INACTIVE) not reflected, got {final_status}"

    durable_status = _replica_status()
    assert durable_status == "INACTIVE", (
        f"replica status regressed on a follow-up ListUserPoolReplicas read, expected "
        f"INACTIVE to persist, got {durable_status!r}"
    )


def _error_code(exc: ClientError) -> str | None:
    try:
        return exc.response["Error"]["Code"]
    except Exception:
        return None


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
