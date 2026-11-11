"""update-user-pool-replica-region-list-server-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-user-pool-replica-region-list-server-enforced"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolReplica for a never-added region fails with ResourceNotFoundException and
    adds no replica; on a created replica, ACTIVE and INACTIVE updates read back as set."""
    cognito = ctx.client("cognito-idp")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    # Replication needs real regions distinct from the pool's home region.
    target_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    unregistered_region = "eu-central-1" if ctx.region != "eu-central-1" else "eu-west-2"
    assert unregistered_region != target_region, "region literals must be pairwise distinct"

    account_id = sts.get_caller_identity()["Account"]
    # Replication requires a multi-Region CMK. Cognito and its backing Identity Store call KMS as
    # their own service principals, so each needs an explicit key-policy grant.
    key_service_principals = ["cognito-idp.amazonaws.com", "identitystore.amazonaws.com"]
    key_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                *[
                    {
                        "Sid": f"AllowUseBy{principal.split('.')[0].replace('-', '')}",
                        "Effect": "Allow",
                        "Principal": {"Service": principal},
                        "Action": [
                            "kms:DescribeKey",
                            "kms:CreateGrant",
                            "kms:Decrypt",
                            "kms:Encrypt",
                            "kms:GenerateDataKey",
                            "kms:GenerateDataKeyWithoutPlaintext",
                            "kms:ReEncrypt*",
                        ],
                        "Resource": "*",
                    }
                    for principal in key_service_principals
                ],
            ],
        }
    )

    try:
        key_id = kms.create_key(
            MultiRegion=True,
            Description="sim2real cognito-idp replica test key",
            Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
            Policy=key_policy,
        )["KeyMetadata"]["KeyId"]
    except ClientError as exc:
        raise AssertionError(
            f"could not create a multi-Region KMS key in this account: "
            f"{exc.response['Error']['Code']} {exc.response['Error'].get('Message')}"
        )
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    try:
        kms.replicate_key(KeyId=key_id, ReplicaRegion=target_region, Policy=key_policy)
    except ClientError as exc:
        raise AssertionError(
            f"could not replicate the multi-Region KMS key into {target_region}: "
            f"{exc.response['Error']['Code']} {exc.response['Error'].get('Message')}"
        )
    ctx.on_cleanup(lambda: _delete_replica_key(ctx, key_id, target_region))
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    def try_create_pool():
        try:
            return _create_user_pool(
                ctx,
                cognito,
                UserPoolTier="PLUS",
                KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
            ), None
        except ClientError as exc:
            return None, exc.response["Error"]

    # A new multi-Region key can briefly be invisible to Cognito (InvalidParameterException
    # "the resource does not exist in this Region"), so pool creation is retried.
    pool_id, _ = _poll_until(
        try_create_pool, lambda result: result[0] is not None, timeout_s=60.0, interval_s=5.0
    )

    code, message = _error(
        lambda: cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=unregistered_region, Status="ACTIVE"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a region never added as a replica, got {code!r}"
    )
    assert message == "Replica not found in the requested region", (
        f"expected the exact {code} message for unregistered region {unregistered_region!r}, "
        f"got {message!r}"
    )

    # ListUserPoolReplicas always includes the pool's own PRIMARY home region, so the list is
    # checked for the rejected region rather than for emptiness.
    replicas_before = cognito.list_user_pool_replicas(UserPoolId=pool_id).get(
        "UserPoolReplicas", []
    )
    assert all(r["RegionName"] != unregistered_region for r in replicas_before), (
        f"rejected call unexpectedly created a replica entry for "
        f"{unregistered_region!r}: {replicas_before!r}"
    )

    def try_create_replica():
        try:
            cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=target_region)
            return True, None
        except ClientError as exc:
            return False, exc.response["Error"]["Code"]

    # The replica KMS key can take a short, undocumented window to become usable
    # cross-Region; poll the only observable signal available (CreateUserPoolReplica itself
    # succeeding) instead of sleeping a fixed duration.
    _poll_until(try_create_replica, lambda result: result[0], timeout_s=120.0, interval_s=5.0)

    def _replica_status():
        for replica in cognito.list_user_pool_replicas(UserPoolId=pool_id).get(
            "UserPoolReplicas", []
        ):
            if replica["RegionName"] == target_region:
                return replica["Status"]
        return None

    # New replicas settle INACTIVE and only UpdateUserPoolReplica makes them ACTIVE; creation
    # can take minutes, hence the long bound.
    _poll_until(
        _replica_status, lambda status: status in ("ACTIVE", "INACTIVE"), timeout_s=800.0, interval_s=10.0
    )

    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=target_region, Status="ACTIVE")
    activated_status = _poll_until(
        _replica_status, lambda status: status == "ACTIVE", timeout_s=60.0, interval_s=5.0
    )
    assert activated_status == "ACTIVE", (
        f"expected replica {target_region!r} to read back ACTIVE, got {activated_status!r}"
    )

    cognito.update_user_pool_replica(
        UserPoolId=pool_id, RegionName=target_region, Status="INACTIVE"
    )
    observed_status = _poll_until(
        _replica_status, lambda status: status == "INACTIVE", timeout_s=60.0, interval_s=5.0
    )
    assert observed_status == "INACTIVE", (
        f"expected replica {target_region!r} to read back INACTIVE, got {observed_status!r}"
    )


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _teardown_pool(cognito, pool_id))
    return pool_id


def _delete_replica_key(ctx, key_id: str, replica_region: str) -> None:
    ctx.client("kms", region=replica_region).schedule_key_deletion(
        KeyId=key_id, PendingWindowInDays=7
    )


def _error(fn):
    """Return the (code, message) fn() is rejected with; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed={last!r})")


def _teardown_pool(cognito, pool_id, timeout_s: float = 1200.0, interval_s: float = 15.0):
    """Delete secondary replicas (ACTIVE ones set INACTIVE first), then the pool, which AWS refuses
    while any secondary replica remains; replica deletion is asynchronous."""
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
