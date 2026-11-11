"""e2e-user-pool-replica-provision-update-sync-teardown."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-user-pool-replica-provision-update-sync-teardown"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replica of a Plus pool with a multi-Region key settles at INACTIVE, is activated and set back
    to INACTIVE with ListUserPoolReplicas following each change, and once deleted is unlisted and
    UpdateUserPoolReplica on it fails with ResourceNotFoundException and its exact message."""
    from botocore.exceptions import ClientError

    cognito = ctx.client("cognito-idp")
    sts = ctx.client("sts")
    kms = ctx.client("kms")
    # A user pool replica MUST live in some second real Region, distinct from ctx.region -- there is
    # no way to derive "some other Region" from ctx alone, so a short literal pick (excluding
    # ctx.region) is the only way to name one.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    account_id = sts.get_caller_identity()["Account"]

    # A PLUS pool needs a multi-Region customer-managed KMS key whose policy admits the principals
    # that resolve it on CreateUserPool: `identitystore.amazonaws.com` (Encrypt/Decrypt/ReEncrypt/
    # GenerateDataKey) and `cognito-idp.amazonaws.com` (DescribeKey during pool creation).
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
                        "Service": ["identitystore.amazonaws.com", "cognito-idp.amazonaws.com"]
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

    key = kms.create_key(
        MultiRegion=True,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description="sim2real-behav cognito replica CMK (multi-Region primary)",
        Policy=key_policy,
        Tags=[{"TagKey": "Name", "TagValue": ctx.unique_name("sim2real-replica-cmk-")}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Replicate the primary key into the replica Region: Cognito requires the CMK to be
    # available in every Region that hosts a user pool replica. ctx.client()'s `region=`
    # override pins this one client to the replica Region while keeping the runner's
    # endpoint/TLS/credential wiring -- the runner's configured real-AWS creds, or the emulator's dummy
    # creds -- so the cross-Region call never falls through to the ambient credential chain.
    kms.replicate_key(KeyId=key_id, ReplicaRegion=replica_region, Policy=key_policy)
    kms_replica = ctx.client("kms", region=replica_region)
    ctx.on_cleanup(lambda: kms_replica.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # AWS documents multi-Region key replication as typically fast but occasionally taking
    # several minutes to propagate. This check's per-run harness timeout is fixed, so treat a
    # replica key that hasn't finished propagating within our budget as an honest
    # environmental skip rather than a failure -- it is a real AWS-side timing prerequisite
    # this harness cannot lengthen, not a bug in the check's assertions.
    try:
        _poll_until(
            lambda: _describe_replica_key_state(kms_replica, key_id),
            lambda state: state == "Enabled",
            timeout_s=180,
            interval_s=10,
        )
    except AssertionError as exc:
        raise AssertionError(
            "multi-Region KMS key replication did not finish propagating to the replica"
            f" Region within this check's time budget: {exc}"
        ) from exc

    try:
        pool = cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-replica-pool-"),
            UserPoolTier="PLUS",
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("FeatureUnavailableInTierException", "TierChangeNotAllowedException"):
            raise AssertionError(
                f"UserPoolTier=PLUS not available in this account/region: {exc.response['Error']['Code']}"
            ) from exc
        raise
    pool_id = pool["UserPool"]["Id"]
    cleanup_deadline: dict = {}
    ctx.on_cleanup(lambda: _delete_pool(cognito, pool_id, cleanup_deadline))

    try:
        created = cognito.create_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "FeatureUnavailableInTierException":
            raise AssertionError(
                f"Multi-Region user pool replication not available in this account/region: {exc.response['Error']['Code']}"
            ) from exc
        raise
    assert created["UserPoolReplica"]["RegionName"] == replica_region

    def _cleanup_replica() -> None:
        """Deactivate, then delete the replica and wait until it is gone; only INACTIVE deletes."""
        deadline = cleanup_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - _CLEANUP_HEADROOM_S)
        while True:
            try:
                replica = _find(cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"])
                if replica is None:
                    return
                if replica["Status"] == "ACTIVE":
                    cognito.update_user_pool_replica(
                        UserPoolId=pool_id, RegionName=replica_region, Status="INACTIVE"
                    )
                elif replica["Status"] == "INACTIVE":
                    cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
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
                raise RuntimeError(f"replica {replica_region} of {pool_id} not deleted within the cleanup budget")
            time.sleep(2)

    ctx.on_cleanup(_cleanup_replica)

    def _find(replicas):
        return next((r for r in replicas if r["RegionName"] == replica_region), None)

    # A new replica can stay CREATING for many minutes, so the wait is generous (700s).
    active = _poll_until(
        lambda: cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"],
        lambda replicas: (_find(replicas) or {}).get("Status") not in (None, "CREATING"),
        timeout_s=700,
        interval_s=15,
    )
    # A new replica leaves CREATING at INACTIVE: created, not yet serving end users.
    settled = _find(active)["Status"]
    assert settled == "INACTIVE", f"a new replica should settle at INACTIVE, got {settled!r}"

    cognito.update_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region, Status="ACTIVE")
    serving = _poll_until(
        lambda: cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"],
        lambda replicas: (_find(replicas) or {}).get("Status") == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    assert _find(serving)["Status"] == "ACTIVE"

    updated = cognito.update_user_pool_replica(
        UserPoolId=pool_id, RegionName=replica_region, Status="INACTIVE"
    )
    assert updated["UserPoolReplica"]["Status"] == "INACTIVE"

    synced = _poll_until(
        lambda: cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"],
        lambda replicas: (_find(replicas) or {}).get("Status") == "INACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert _find(synced)["Status"] == "INACTIVE"

    cognito.delete_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)

    # A replica stays listed as DELETING for minutes, like its CREATING phase; capped by the run budget.
    left = ctx.time_left()
    remaining = _poll_until(
        lambda: cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"],
        lambda replicas: _find(replicas) is None,
        timeout_s=600.0 if left is None else max(60.0, min(600.0, left - 30.0)),
        interval_s=2,
    )
    assert _find(remaining) is None

    # A deleted replica must be gone AND unusable: a mutation targeting the dead RegionName
    # must fail with the specific not-found code, not just be absent from the list.
    dead_code, dead_message = _client_error(
        lambda: cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=replica_region, Status="ACTIVE"
        )
    )
    assert dead_code == "ResourceNotFoundException", (
        f"UpdateUserPoolReplica on a deleted replica must fail with ResourceNotFoundException,"
        f" got {dead_code}"
    )
    assert dead_message == "Replica not found in the requested region", dead_message


_CLEANUP_S = 1800.0  # the suite's cleanup budget, shared by the check's teardowns
_CLEANUP_HEADROOM_S = 120.0
_REPLICA_BUSY = "Replica cannot be deleted while in "
_REPLICAS_LEFT = (
    "Cannot delete user pool that has secondary replicas. "
    "Please delete all replicas before deleting the user pool."
)


def _delete_pool(cognito, pool_id, cleanup_deadline: dict) -> None:
    """Delete the pool; retry while a deleted replica is still attached, return if already gone."""
    from botocore.exceptions import ClientError

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


def _client_error(fn):
    """Call fn(); return its botocore Error (Code, Message). An unexpected success raises, as
    accepting a call AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not satisfied within {timeout_s}s (last observed: {last!r})")


def _describe_replica_key_state(kms_client, key_id: str):
    """Multi-Region key replication is eventually consistent: DescribeKey against the
    replica Region can 404 with NotFoundException for a brief window right after
    ReplicateKey returns, before propagation completes. Treat that as "not ready yet"
    (None) rather than a hard failure so the caller's poll loop can retry."""
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
