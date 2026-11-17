"""stop-replication-to-replica-on-a-primary-secret-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-replication-to-replica-on-a-primary-secret-rejected"
GROUP = "validation"
SERVICES = ["secretsmanager"]

# Any region other than the primary's own works for cross-region replication; this literal is
# just an arbitrary second region, not a pin to a specific one.
_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s:.0f}s for {description}; last observation was {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _try_get(sm, secret_id: str):
    try:
        return sm.get_secret_value(SecretId=secret_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _reap(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _detach_and_reap_primary(sm, primary_arn: str, replica_region: str) -> None:
    """Drop any attached replica before deleting the primary; a live replica blocks DeleteSecret."""
    try:
        sm.remove_regions_from_replication(SecretId=primary_arn, RemoveReplicaRegions=[replica_region])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 45.0
    while True:
        try:
            desc = sm.describe_secret(SecretId=primary_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                break
            raise
        if replica_region not in [r["Region"] for r in desc.get("ReplicationStatus", [])]:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"replica {replica_region} still attached to {primary_arn} during cleanup")
        time.sleep(2.0)
    _reap(sm, primary_arn)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopReplicationToReplica refuses a primary secret's own ARN, with a message that names the
    replica's Region once one exists, while the identical call issued from a live replica's
    Region promotes that replica instead.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/standalone-secret.html
    """
    sm = ctx.client("secretsmanager")
    replica_region = (
        _REPLICA_REGION_FALLBACK if ctx.region == _REPLICA_REGION_PRIMARY else _REPLICA_REGION_PRIMARY
    )
    assert replica_region != ctx.region, (
        f"the replica region must differ from the primary; both resolved to {ctx.region!r}"
    )
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-behav-smstop-")
    created = sm.create_secret(
        Name=name,
        SecretString="sim2real-not-a-real-secret",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    primary_arn = created["ARN"]
    ctx.on_cleanup(lambda: _detach_and_reap_primary(sm, primary_arn, replica_region))
    # Cleanup is LIFO; this runs before the primary's, since a promoted secret in the replica
    # Region is independent of the primary and the primary's own teardown never reaches it.
    ctx.on_cleanup(lambda: _reap(sm_replica, name))

    # A never-replicated secret refuses the same call for the same reason: it has no replica to
    # promote either. Establishing this first keeps the two refusals distinguishable: the model
    # error that actually fires is the same on both, but the second also rules out a target that
    # merely checks replica presence rather than primary/standalone status.
    code, message = _error(lambda: sm.stop_replication_to_replica(SecretId=primary_arn))
    assert code == "InvalidParameterException", (
        f"StopReplicationToReplica on an unreplicated secret must be refused, got {code!r}: {message!r}"
    )
    expected = "Operation not permitted on a primary/standalone secret."
    assert message == expected, f"unexpected message for an unreplicated secret: {message!r}"

    resp = sm.replicate_secret_to_regions(SecretId=primary_arn, AddReplicaRegions=[{"Region": replica_region}])
    failed = [r for r in resp.get("ReplicationStatus", []) if r.get("Status") == "Failed"]
    assert not failed, f"ReplicateSecretToRegions reported Failed immediately: {failed!r}"
    _poll_until(
        lambda: sm.describe_secret(SecretId=primary_arn),
        lambda d: any(
            r.get("Region") == replica_region and r.get("Status") == "InSync"
            for r in d.get("ReplicationStatus", [])
        ),
        timeout_s=180.0,
        interval_s=2.0,
        description=f"the {replica_region} replica to reach InSync",
    )

    code, message = _error(lambda: sm.stop_replication_to_replica(SecretId=primary_arn))
    assert code == "InvalidParameterException", (
        f"StopReplicationToReplica on the now-replicated primary must still be refused, got "
        f"{code!r}: {message!r}"
    )
    expected_replicated = "Operation not permitted on a primary secret. Call must be made in replica secret's region."
    assert message == expected_replicated, f"unexpected message on the replicated primary: {message!r}"

    # Effect absent: the refused call left the replica link in place.
    after_refusal = sm.describe_secret(SecretId=primary_arn)
    assert any(r.get("Region") == replica_region for r in after_refusal.get("ReplicationStatus", [])), (
        f"the refused call must leave the replica attached, got {after_refusal.get('ReplicationStatus')!r}"
    )

    # Positive control: the identical operation on the replica, not the primary, succeeds and
    # promotes it to a standalone secret.
    sm_replica.stop_replication_to_replica(SecretId=name)
    after_stop = _poll_until(
        lambda: sm.describe_secret(SecretId=primary_arn),
        lambda d: replica_region not in [r["Region"] for r in d.get("ReplicationStatus", [])],
        timeout_s=180.0,
        interval_s=2.0,
        description=f"the primary to drop {replica_region} after StopReplicationToReplica",
    )
    assert replica_region not in [r["Region"] for r in after_stop.get("ReplicationStatus", [])], (
        f"the primary still lists the promoted region: {after_stop.get('ReplicationStatus')!r}"
    )
    promoted = _try_get(sm_replica, name)
    assert promoted is not None, (
        f"StopReplicationToReplica issued from the replica Region must promote it to a readable "
        f"standalone secret there"
    )
    assert promoted["SecretString"] == "sim2real-not-a-real-secret", (
        f"the promoted secret must keep its plaintext, got {promoted['SecretString']!r}"
    )

    # The promoted secret is itself a primary/standalone secret now, so it refuses the same call
    # for the same reason the original primary did.
    code, message = _error(lambda: sm_replica.stop_replication_to_replica(SecretId=name))
    assert code == "InvalidParameterException", (
        f"StopReplicationToReplica on the just-promoted secret must be refused, got {code!r}: {message!r}"
    )
    assert message == expected, f"unexpected message on the promoted secret: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
