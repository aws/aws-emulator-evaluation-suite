"""operation-not-enabled-signing-cert."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "operation-not-enabled-signing-cert"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']


def _error(fn):
    """Run fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(fn, pred, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


def _retry_throttled(fn, *, max_attempts=8, base_delay=1.0):
    """Retry fn() with exponential backoff on TooManyRequestsException so a
    transient account-wide rate limit isn't mistaken for a business error."""
    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


_NOT_ENABLED = "This operation is not enabled in this region for this User Pool"
_CLEANUP_S = 1800.0  # the suite's cleanup budget, shared by the check's teardowns
_CLEANUP_HEADROOM_S = 120.0
_REPLICA_BUSY = "Replica cannot be deleted while in "
_REPLICAS_LEFT = (
    "Cannot delete user pool that has secondary replicas. "
    "Please delete all replicas before deleting the user pool."
)


def _delete_replica(c, pool_id, region_name, cleanup_deadline: dict) -> None:
    """Wait out CREATING, deactivate, then delete the replica until it is gone; only INACTIVE deletes."""
    deadline = cleanup_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - _CLEANUP_HEADROOM_S)
    while True:
        try:
            replicas = c.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
            status = next((r["Status"] for r in replicas if r["RegionName"] == region_name), None)
            if status is None:
                return
            if status == "ACTIVE":
                c.update_user_pool_replica(UserPoolId=pool_id, RegionName=region_name, Status="INACTIVE")
            elif status == "INACTIVE":
                c.delete_user_pool_replica(UserPoolId=pool_id, RegionName=region_name)
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


def _delete_pool(c, pool_id, cleanup_deadline: dict) -> None:
    """Delete the pool; retry while a deleted replica is still attached, return if already gone."""
    deadline = cleanup_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - _CLEANUP_HEADROOM_S)
    while True:
        try:
            c.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            refused = (error["Code"], error.get("Message")) == ("InvalidParameterException", _REPLICAS_LEFT)
            if not refused or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _regional_client(ctx, service, region):
    """A client for `service` pinned to `region`, against the same target as ctx.client()."""
    return ctx.client(service, region=region)


def _new_multiregion_kms_key(ctx, replica_region):
    """Create a multi-Region CMK, grant cognito-idp use of it, replicate it into
    replica_region (required for CreateUserPoolReplica / Plus tier). Returns the
    primary ARN."""
    kms_home = ctx.client("kms")
    resp = kms_home.create_key(
        MultiRegion=True,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-behav-cognito-mrr-"),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    arn = resp["KeyMetadata"]["Arn"]
    account_id = arn.split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCognitoService",
                "Effect": "Allow",
                "Principal": {
                    "Service": ["cognito-idp.amazonaws.com", "identitystore.amazonaws.com"]
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKeyWithoutPlainText",
                    "kms:GenerateDataKeyWithoutPlaintext",
                    "kms:DescribeKey",
                ],
                "Resource": "*",
            },
        ],
    }
    kms_home.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
    ctx.on_cleanup(lambda _k=key_id: kms_home.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    kms_home.replicate_key(KeyId=key_id, ReplicaRegion=replica_region, Policy=json.dumps(policy))
    kms_replica = _regional_client(ctx, "kms", replica_region)
    ctx.on_cleanup(lambda _k=key_id: kms_replica.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if kms_replica.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Enabled":
                break
        except Exception:
            pass
        time.sleep(3)
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSigningCertificate against a user pool replica region is rejected, never served,
    while the same UserPoolId keeps working in the primary region."""
    c = ctx.client("cognito-idp")
    # Cross-region user pool replication needs a second, distinct real AWS region;
    # any pair works, so this pins one rather than deriving it from ctx.region.
    replica_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    kms_key_arn = _new_multiregion_kms_key(ctx, replica_region)

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        UserPoolTier="PLUS",
        KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": kms_key_arn},
    )["UserPool"]["Id"]
    cleanup_deadline: dict = {}
    ctx.on_cleanup(lambda: _delete_pool(c, pool_id, cleanup_deadline))

    # The primary region can always fetch its own signing certificate.
    primary_cert = c.get_signing_certificate(UserPoolId=pool_id)["Certificate"]
    assert primary_cert, "primary-region GetSigningCertificate returned an empty certificate"

    _retry_throttled(
        lambda: c.create_user_pool_replica(UserPoolId=pool_id, RegionName=replica_region)
    )
    ctx.on_cleanup(lambda: _delete_replica(c, pool_id, replica_region, cleanup_deadline))

    replica_client = _regional_client(ctx, "cognito-idp", replica_region)

    def find_replica():
        for r in c.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]:
            if r["RegionName"] == replica_region:
                return r
        return None

    replica = _poll_until(
        find_replica,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=5,
        description="replica visible in ListUserPoolReplicas",
    )
    assert replica["Status"] in ("CREATING", "ACTIVE", "INACTIVE"), replica["Status"]

    # A replica region that does not yet know the pool answers ResourceNotFoundException; poll
    # (bounded) past that to the region's settled refusal, then pin it.
    not_found = ("ResourceNotFoundException", f"User pool {pool_id} does not exist.")
    answer = _poll_until(
        lambda: _error(lambda: replica_client.get_signing_certificate(UserPoolId=pool_id)),
        lambda got: got != not_found,
        timeout_s=40,
        interval_s=3,
        description="the replica region to recognize the user pool",
    )
    assert answer == ("OperationNotEnabledException", _NOT_ENABLED), (
        f"expected OperationNotEnabledException {_NOT_ENABLED!r} requesting the signing certificate "
        f"from the replica region, got {answer!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
