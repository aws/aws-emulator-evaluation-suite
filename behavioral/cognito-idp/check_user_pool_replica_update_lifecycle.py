"""user-pool-replica-update-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "user-pool-replica-update-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

# The suite cleanup budget, shared by the replica teardown's delete retries and its gone-wait.
_CLEANUP_S = 1800.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replica of a Plus pool with a multi-Region key leaves CREATING, moves to ACTIVE and back to
    INACTIVE as ListUserPoolReplicas reads, and DeleteUserPoolReplica removes it from that listing."""
    cognito = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-replica-pool-")

    # Any second Region works as the replica target; these two are picked only because they
    # are guaranteed distinct from ctx.region, not because either is itself pinned.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    # CreateUserPoolReplica needs the pool encrypted with a customer-managed multi-Region KMS key,
    # so the check creates one.
    key_arn = _create_multiregion_cmk(ctx, replica_region)

    try:
        pool_id = cognito.create_user_pool(
            PoolName=pool_name,
            UserPoolTier="PLUS",
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["UserPool"]["Id"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("FeatureUnavailableInTierException", "TierChangeNotAllowedException"):
            raise AssertionError(
                f"the Plus feature tier required for multi-Region replication is not "
                f"available for this account/region ({code})"
            )
        raise
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    try:
        cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
    except ClientError as exc:
        error = exc.response["Error"]
        code = error["Code"]
        if code == "FeatureUnavailableInTierException":
            raise AssertionError(
                f"multi-Region replication unavailable for this Plus-tier pool/account ({code})"
            )
        if code == "InvalidParameterException" and "KMS key" in error.get("Message", ""):
            raise AssertionError(
                "CreateUserPoolReplica still reports a missing customer-managed multi-Region KMS "
                f"key even though this check provisioned one ({key_arn}) and attached it via "
                f"KeyConfiguration: {error.get('Message')!r}"
            )
        raise
    ctx.on_cleanup(lambda: _delete_replica_and_wait(cognito, pool_id, replica_region))

    # Provisioning a replica takes several minutes (about 240-430 s on AWS), so this first poll
    # waits up to 800 s; the ACTIVE and delete transitions below are fast and wait 180 s.
    status = _poll_until(
        lambda: _replica_status(cognito, pool_id, replica_region),
        lambda s: s is not None and s != "CREATING",
        timeout_s=800.0,
        interval_s=5.0,
    )
    assert status in ("INACTIVE", "ACTIVE"), status

    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region, Status="ACTIVE")
    active_status = _poll_until(
        lambda: _replica_status(cognito, pool_id, replica_region),
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert active_status == "ACTIVE", f"expected ACTIVE after UpdateUserPoolReplica, got {active_status!r}"

    # Real AWS refuses to delete an ACTIVE replica, so it is deactivated first.
    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region, Status="INACTIVE")
    inactive_status = _poll_until(
        lambda: _replica_status(cognito, pool_id, replica_region),
        lambda s: s == "INACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert inactive_status == "INACTIVE", f"expected INACTIVE after deactivation, got {inactive_status!r}"

    cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
    # A replica can stay DELETING for well over 3 minutes on AWS.
    left = ctx.time_left()
    gone = _poll_until(
        lambda: _replica_status(cognito, pool_id, replica_region),
        lambda s: s is None,
        timeout_s=900.0 if left is None else max(0.0, min(900.0, left - 60.0)),
        interval_s=2.0,
    )
    assert gone is None, f"expected the replica gone from ListUserPoolReplicas, got status={gone!r}"


def _replica_status(cognito, pool_id: str, region_name: str):
    resp = cognito.list_user_pool_replicas(UserPoolId=pool_id)
    for replica in resp.get("UserPoolReplicas", []):
        if replica.get("RegionName") == region_name:
            return replica.get("Status")
    return None


def _delete_replica_and_wait(cognito, pool_id: str, region_name: str) -> None:
    # Only an INACTIVE replica can be deleted: an ACTIVE one is deactivated first, and a
    # CREATING or still-ACTIVE one refuses the delete until its transition ends.
    deadline = time.monotonic() + _CLEANUP_S
    deactivated = False
    while (status := _replica_status(cognito, pool_id, region_name)) not in (None, "DELETING"):
        try:
            if status == "ACTIVE" and not deactivated:
                cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=region_name, Status="INACTIVE")
                deactivated = True
            else:
                cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=region_name)
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
    _poll_until(
        lambda: _replica_status(cognito, pool_id, region_name),
        lambda s: s is None,
        timeout_s=max(deadline - time.monotonic(), 0.0),
        interval_s=2.0,
    )


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


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
