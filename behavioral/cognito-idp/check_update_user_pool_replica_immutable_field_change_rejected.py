"""update-user-pool-replica-immutable-field-change-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-replica-immutable-field-change-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolReplica rejects an out-of-range Status value (the only mutable
    field the operation exposes) with InvalidParameterException, leaving the real
    replica's status untouched, while a real ACTIVE/INACTIVE transition succeeds."""
    cognito = ctx.client("cognito-idp")
    kms = ctx.client("kms")

    # Only needs to differ from ctx.region -- no resource is pinned to either literal.
    target_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    kms_replica = ctx.client("kms", region=target_region)

    # CreateUserPoolReplica rejects with InvalidParameterException unless the pool already carries a
    # customer-managed, multi-Region KMS key with a replica key present in the destination region;
    # this is not documented anywhere the SDK surfaces before the call. Provisioned
    # in-check rather than assumed pre-attached.
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

    replica_key_arn = kms.replicate_key(
        KeyId=key_arn, ReplicaRegion=target_region, Policy=key_policy
    )["ReplicaKeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: kms_replica.schedule_key_deletion(KeyId=replica_key_arn, PendingWindowInDays=7)
    )
    _wait_kms_key_enabled(kms_replica, replica_key_arn, timeout_s=120)

    try:
        pool_id = cognito.create_user_pool(
            PoolName=ctx.unique_name("sim2real-replicaimm-"),
            UserPoolTier="PLUS",
            KeyConfiguration={"KeyType": "CUSTOMER_MANAGED_KEY", "KmsKeyArn": key_arn},
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-replicaimm"},
        )["UserPool"]["Id"]
    except ClientError as err:
        raise AssertionError(
            "Creating a Plus-tier user pool with a multi-Region CMK (required for "
            "CreateUserPoolReplica/UpdateUserPoolReplica) failed with "
            f"{err.response['Error']['Code']}."
        ) from err
    ctx.on_cleanup(lambda: _teardown_pool(cognito, pool_id))

    try:
        create_resp = cognito.create_user_pool_replica(
            UserPoolId=pool_id, RegionName=target_region
        )
    except ClientError as err:
        raise AssertionError(
            "CreateUserPoolReplica with a valid secondary region and a correctly "
            f"provisioned multi-Region CMK failed with {err.response['Error']['Code']}; "
            "cannot exercise UpdateUserPoolReplica without a real replica."
        ) from err
    assert create_resp["UserPoolReplica"]["RegionName"] == target_region

    # Status is the only field UpdateUserPoolReplica lets a caller mutate; it is
    # constrained to ACTIVE|INACTIVE. Bypass client-side enum validation so a
    # nonsense value actually reaches the service instead of failing locally. This is
    # server-side parameter-shape validation, independent of the replica's own
    # provisioning state -- real AWS's message names the value
    # and the enum set ("Member must satisfy enum value set: [ACTIVE, INACTIVE]"),
    # not the replica's CREATING/ACTIVE/INACTIVE lifecycle state -- so it is exercised
    # without waiting on that state.
    raw = _client_no_param_validation(ctx, "cognito-idp")
    prior_status = _replica_status(cognito, pool_id, target_region)
    assert prior_status is not None, f"ListUserPoolReplicas does not list the {target_region} replica"
    code, message = _error_detail(
        lambda: raw.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=target_region, Status="SUSPENDED_NOT_A_REAL_STATUS"
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = (
        "1 validation error detected: Value 'SUSPENDED_NOT_A_REAL_STATUS' at 'status' failed to "
        "satisfy constraint: Member must satisfy enum value set: [ACTIVE, INACTIVE]"
    )
    assert message == expected_message, (
        f"expected the exact enum-constraint message {expected_message!r}, got {message!r} -- "
        "a different message would mean the rejection is about something other than the "
        "out-of-range value, such as replica readiness"
    )

    # effect absent: the replica's real status is untouched by the rejected mutation
    replicas = cognito.list_user_pool_replicas(UserPoolId=pool_id)["UserPoolReplicas"]
    match = next(r for r in replicas if r["RegionName"] == target_region)
    # Only provisioning may move the status on (CREATING -> ACTIVE); the rejected call never does.
    allowed = {prior_status} | ({"ACTIVE"} if prior_status == "CREATING" else set())
    assert match["Status"] in allowed, (
        f"replica status before the rejected update was {prior_status!r}, after it {match['Status']!r}"
    )

    # positive control: a real, valid status transition succeeds and is confirmed on
    # an independent read at the destination (ListUserPoolReplicas), never on the
    # mutating call's own response.
    #
    # Real AWS rejects even a VALID Status value with InvalidParameterException("Replica cannot be
    # updated while in CREATING status") for as long as the replica is still CREATING. That is
    # provisioning latency, so the positive control waits for CREATING to clear first.
    _poll_until(
        lambda: _replica_status(cognito, pool_id, target_region),
        lambda s: s is not None and s != "CREATING",
        timeout_s=900.0,
    )
    try:
        cognito.update_user_pool_replica(
            UserPoolId=pool_id, RegionName=target_region, Status="INACTIVE"
        )
    except ClientError as err:
        pos_error = err.response.get("Error", {})
        raise AssertionError(
            f"UpdateUserPoolReplica(Status=INACTIVE), a valid transition, was rejected with "
            f"{pos_error.get('Code')}: {pos_error.get('Message')!r} -- the replica had already "
            "left CREATING by the poll above, so this is a real refusal of a valid transition, "
            "not provisioning latency"
        ) from err
    final_status = _poll_until(
        lambda: _replica_status(cognito, pool_id, target_region),
        lambda s: s == "INACTIVE",
        timeout_s=180.0,
    )
    assert final_status == "INACTIVE", f"expected INACTIVE on an independent read, got {final_status}"


def _error_detail(fn):
    """Run fn and return the (code, message) AWS refused it with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {}).get("Code"), err.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _client_no_param_validation(ctx, service):
    # ctx.client's own `config` override merges over the runner's base config (the run's
    # creds, retry/host-prefix wiring) rather than replacing it -- a bare boto3.client()
    # here would drop the run's credentials and silently fall back to the ambient
    # chain, bypassing the account guard the runner enforces.
    return ctx.client(service, config=Config(parameter_validation=False, retries={"max_attempts": 2}))


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


def _replica_status(cognito, pool_id: str, region_name: str):
    resp = cognito.list_user_pool_replicas(UserPoolId=pool_id)
    for replica in resp.get("UserPoolReplicas", []):
        if replica.get("RegionName") == region_name:
            return replica.get("Status")
    return None


def _poll_until(probe, predicate, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


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
