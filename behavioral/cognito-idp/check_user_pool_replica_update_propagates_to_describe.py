"""user-pool-replica-update-propagates-to-describe."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "user-pool-replica-update-propagates-to-describe"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]
_CLEANUP_S = 1800.0  # the suite's cleanup budget, shared by the check's teardowns
_REPLICAS_LEFT = (
    "Cannot delete user pool that has secondary replicas. "
    "Please delete all replicas before deleting the user pool."
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each UpdateUserPoolReplica status change (ACTIVE, INACTIVE, ACTIVE) is reflected by a
    fresh ListUserPoolReplicas read, so the update mutates stored state rather than echoing
    the request."""
    from botocore.exceptions import ClientError

    idp = ctx.client("cognito-idp")
    sts = ctx.client("sts")
    kms = ctx.client("kms")

    # A replica needs a second, distinct region to replicate into.
    target_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    account_id = sts.get_caller_identity()["Account"]

    # CreateUserPoolReplica rejects a pool with InvalidParameterException unless it is
    # encrypted with a multi-Region customer-managed KMS key.
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
                    # CreateUserPool fails with InvalidParameterException unless both
                    # identitystore.amazonaws.com (the backing store of Plus-tier pools) and
                    # cognito-idp.amazonaws.com can use the key.
                    "Sid": "AllowCognitoAndIdentityStoreServiceAccess",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["identitystore.amazonaws.com", "cognito-idp.amazonaws.com"]
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
        Description="sim2real cognito replica-update CMK (multi-Region primary)",
        Policy=key_policy,
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Replicate the primary key into the target Region: Cognito requires the CMK to be
    # available in every Region that hosts a user pool replica.
    kms.replicate_key(KeyId=key_id, ReplicaRegion=target_region, Policy=key_policy)
    kms_replica = ctx.client("kms", region=target_region)
    ctx.on_cleanup(lambda: kms_replica.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    try:
        _poll_until(
            lambda: _kms_key_state(kms_replica, key_id),
            lambda state: state == "Enabled",
            timeout_s=60.0,
            interval_s=10.0,
        )
    except AssertionError as exc:
        raise AssertionError(
            f"multi-Region KMS key replication did not finish propagating to {target_region}"
            f" within budget: {exc}"
        ) from exc

    try:
        pool_id = idp.create_user_pool(
            PoolName=ctx.unique_name("sim2real-replica-update-pool-"),
            UserPoolTier="PLUS",
            UserPoolTags={"sim2real-check": CHECK},
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
        )["UserPool"]["Id"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("FeatureUnavailableInTierException", "TierChangeNotAllowedException"):
            raise AssertionError(f"UserPoolTier=PLUS not available in this account/region: {code}") from exc
        raise
    cleanup_deadline = time.monotonic() + _CLEANUP_S
    ctx.on_cleanup(lambda: _delete_pool(idp, pool_id, cleanup_deadline))

    try:
        idp.create_user_pool_replica(UserPoolId=pool_id, RegionName=target_region)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "FeatureUnavailableInTierException":
            raise AssertionError(
                f"multi-Region user pool replication not available in this account/region: {code}"
            ) from exc
        raise
    ctx.on_cleanup(lambda: _delete_replica_and_wait(idp, pool_id, target_region, cleanup_deadline))
    # A new replica can leave CREATING and rest at INACTIVE without any update, so the first
    # wait accepts either settled value; the updates below drive the transitions.
    initial_status = _wait_replica_status(
        ctx, pool_id, target_region, {"ACTIVE", "INACTIVE"}, timeout_s=580.0
    )
    assert initial_status in ("ACTIVE", "INACTIVE"), initial_status

    idp.update_user_pool_replica(UserPoolId=pool_id, RegionName=target_region, Status="ACTIVE")
    _wait_replica_status(ctx, pool_id, target_region, {"ACTIVE"}, timeout_s=60.0)

    idp.update_user_pool_replica(UserPoolId=pool_id, RegionName=target_region, Status="INACTIVE")
    _wait_replica_status(ctx, pool_id, target_region, {"INACTIVE"}, timeout_s=60.0)

    idp.update_user_pool_replica(UserPoolId=pool_id, RegionName=target_region, Status="ACTIVE")
    _wait_replica_status(ctx, pool_id, target_region, {"ACTIVE"}, timeout_s=60.0)


def _wait_replica_status(
    ctx, pool_id: str, region_name: str, expected: set[str], timeout_s: float = 180.0
) -> str:
    idp = ctx.client("cognito-idp")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        replicas = idp.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
        matching = [r for r in replicas if r["RegionName"] == region_name]
        if matching:
            last = matching[0]["Status"]
            if last in expected:
                return last
        time.sleep(3.0)
    raise AssertionError(f"replica in {region_name} never reached status={expected} (last={last})")


def _replica_status(idp, pool_id: str, region_name: str):
    for r in idp.list_user_pool_replicas(UserPoolId=pool_id).get("UserPoolReplicas", []):
        if r["RegionName"] == region_name:
            return r["Status"]
    return None


def _delete_replica_and_wait(idp, pool_id: str, region_name: str, deadline: float) -> None:
    # Only an INACTIVE replica can be deleted: an ACTIVE one is deactivated first, and a
    # CREATING or still-ACTIVE one refuses the delete until its transition ends.
    from botocore.exceptions import ClientError

    deactivated = False
    while (status := _replica_status(idp, pool_id, region_name)) not in (None, "DELETING"):
        try:
            if status == "ACTIVE" and not deactivated:
                idp.update_user_pool_replica(UserPoolId=pool_id, RegionName=region_name, Status="INACTIVE")
                deactivated = True
            else:
                idp.delete_user_pool_replica(UserPoolId=pool_id, RegionName=region_name)
                break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if (
                code != "InvalidParameterException"
                or status not in ("CREATING", "ACTIVE")
                or time.monotonic() >= deadline
            ):
                raise
        time.sleep(2.0)
    # A replica can stay DELETING for minutes on AWS; the pool cannot be deleted until it is gone.
    _poll_until(
        lambda: _replica_status(idp, pool_id, region_name),
        lambda s: s is None,
        timeout_s=max(deadline - time.monotonic(), 0.0),
        interval_s=2.0,
    )


def _delete_pool(idp, pool_id: str, deadline: float) -> None:
    """Delete the pool; retry while a deleted replica is still attached, return if already gone."""
    from botocore.exceptions import ClientError

    while True:
        try:
            idp.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            refused = (error["Code"], error.get("Message")) == ("InvalidParameterException", _REPLICAS_LEFT)
            if not refused or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not satisfied within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)
        last = probe()
    return last


def _kms_key_state(kms_client, key_id: str):
    """Return the key's state, or None while DescribeKey in the replica Region still answers
    NotFoundException: multi-Region key replication is eventually consistent."""
    from botocore.exceptions import ClientError

    try:
        return kms_client.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
