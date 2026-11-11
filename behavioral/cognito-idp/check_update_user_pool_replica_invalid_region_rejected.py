"""update-user-pool-replica-invalid-region-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-replica-invalid-region-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/UpdateUserPoolReplica with a RegionName that is not an AWS region is refused with
    InvalidParameterException, while a valid region passes that validation (ResourceNotFound before
    a replica exists, then a replica that settles INACTIVE and can be driven ACTIVE -> INACTIVE)."""
    cognito = ctx.client("cognito-idp")
    valid_region = "eu-west-1" if ctx.region != "eu-west-1" else "eu-central-1"
    key_arn = _create_multiregion_cmk(ctx, valid_region)
    pool_id = _create_user_pool(ctx, key_arn)

    bad_region = "not-a-real-region"
    code, message = _error(lambda: cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=bad_region))
    if code == "FeatureUnavailableInTierException":
        raise AssertionError(
            "multi-region replication (CreateUserPoolReplica/UpdateUserPoolReplica) "
            "requires a feature-plan tier this pool/account doesn't have, so "
            "region-name validation can't be exercised here"
        )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Invalid region name", (
        f"expected the exact {code} message for RegionName {bad_region!r}, got {message!r}"
    )

    # First, with no replica in existence: the syntactically valid region clears the format
    # check and fails for a different reason. This must run BEFORE the replica exists.
    code2, message2 = _error(
        lambda: cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=valid_region, Status="ACTIVE"
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert message2 == "Replica not found in the requested region", (
        f"expected the exact {code2} message for a replica that does not exist yet, got {message2!r}"
    )

    # Then provision the replica (slow and cross-region on real AWS); the terminal read is
    # independent (ListUserPoolReplicas), not the create call's own echo.
    cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=valid_region)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=valid_region))
    assert _replica_status(cognito, pool_id, valid_region) is not None, "created replica not listed"

    # UpdateUserPoolReplica rejects a replica still in CREATING, so wait for provisioning to
    # finish (it takes several minutes); a fresh replica rests at INACTIVE, not ACTIVE.
    status = _wait_replica_status(
        cognito, pool_id, valid_region, lambda s: s != "CREATING", timeout_s=900.0, interval_s=15.0, no_raise=True
    )
    if status == "CREATING":
        raise AssertionError(
            "CreateUserPoolReplica was accepted (real KMS multi-Region CMK attached, PLUS "
            "tier) but the replica never left CREATING within 900s on this account -- "
            "multi-region user pool replication cannot be exercised end-to-end here"
        )

    assert status == "INACTIVE", (
        f"expected a freshly created replica to settle at INACTIVE (activation is an explicit "
        f"administrator action, never automatic), got {status!r}"
    )

    # The positive control for the region argument: the SAME syntactically-valid region that
    # the format check let through drives a real state transition, so the rejection above
    # is specific to the malformed region and not to UpdateUserPoolReplica being unusable.
    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=valid_region, Status="ACTIVE")
    active_status = _wait_replica_status(
        cognito, pool_id, valid_region, lambda s: s == "ACTIVE", timeout_s=180.0, interval_s=5.0
    )
    assert active_status == "ACTIVE", active_status

    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=valid_region, Status="INACTIVE")
    final_status = _wait_replica_status(
        cognito, pool_id, valid_region, lambda s: s == "INACTIVE", timeout_s=180.0, interval_s=5.0
    )
    assert final_status == "INACTIVE", final_status


# ===== helpers =====


def _error(fn):
    """Run fn and return the (code, message) AWS refused it with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _create_user_pool(ctx, key_arn):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTier="PLUS",
        KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
        UserPoolTags={"sim2real": "cognito-idp-replica-region-check"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_after_replicas(cognito, pool_id))
    return pool_id


def _delete_pool_after_replicas(cognito, pool_id, timeout_s: float = 900.0, interval_s: float = 15.0):
    """DeleteUserPool refuses a pool that still lists a secondary replica, and replica deletion
    is asynchronous, so wait for every non-PRIMARY replica to drop out of the list first."""
    deadline = time.monotonic() + timeout_s
    while True:
        replicas = cognito.list_user_pool_replicas(UserPoolId=pool_id).get("UserPoolReplicas", [])
        secondaries = [r for r in replicas if r.get("Role") != "PRIMARY"]
        if not secondaries or time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    cognito.delete_user_pool(UserPoolId=pool_id)


def _create_multiregion_cmk(ctx, replica_region):
    # Real AWS rejects CreateUserPoolReplica/UpdateUserPoolReplica for a syntactically valid
    # region with InvalidParameterException ("User pool needs a customer-managed KMS key for
    # multi-region replication") unless the pool's own key is a multi-region CMK -- so that CMK
    # is a real in-check prerequisite, not an external entitlement.
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
        Description="sim2real cognito-idp user-pool-replica CMK",
        Tags=[{"TagKey": "sim2real", "TagValue": "cognito-idp-replica-region-check"}],
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
