"""replication-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail but SUCCEEDED")

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

def _drop_replica(sm, secret_id, region):
    """Remove a replica so the primary's own teardown can delete it; a no-op when none remains."""
    try:
        sm.remove_regions_from_replication(SecretId=secret_id, RemoveReplicaRegions=[region])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2):
    """Poll probe() until predicate() holds; return the last result (raises nothing on timeout)."""
    import time
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last

CHECK = "replication-lifecycle"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replicate -> duplicate-region tolerated -> delete-blocked-by-replica -> remove -> delete succeeds."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    created = _create_secret(
        sm, ctx, name=name, secret_string="value",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    # any region other than the primary's own works for cross-region replication; the
    # literal is just an arbitrary second region, not a pin to a specific one.
    replica_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    # bounded wait for replication convergence; a target that converges sooner exits sooner
    timeout_s = 120

    # a standalone (non-replica) secret cannot be "stopped" from replication
    stop_code, stop_message = _error(lambda: sm.stop_replication_to_replica(SecretId=name))
    assert stop_code == "InvalidParameterException", (
        f"StopReplicationToReplica on a non-replica secret must be rejected, got {stop_code}"
    )
    assert stop_message == (
        "Operation not permitted on a primary/standalone secret."
    ), f"StopReplicationToReplica on a non-replica secret returned message {stop_message!r}"

    # registered after the secret's own teardown, so LIFO cleanup drops the replica first
    ctx.on_cleanup(lambda: _drop_replica(sm, name, replica_region))
    sm.replicate_secret_to_regions(
        SecretId=name, AddReplicaRegions=[{"Region": replica_region}]
    )

    desc = _poll_until(
        lambda: sm.describe_secret(SecretId=name),
        lambda d: any(
            r.get("Region") == replica_region and r.get("Status") in ("InSync", "Failed")
            for r in d.get("ReplicationStatus", [])
        ),
        timeout_s=timeout_s,
    )
    replica = [r for r in desc.get("ReplicationStatus", []) if r.get("Region") == replica_region]
    assert replica, "replica region must appear in ReplicationStatus"
    assert replica[0].get("Status") == "InSync", f"replication did not reach InSync: {replica[0]}"
    assert replica[0].get("StatusMessage") == "Replication succeeded", (
        f"an InSync replica reported StatusMessage {replica[0].get('StatusMessage')!r}"
    )

    # Re-replicating to a region that already hosts a replica does NOT raise: the API
    # returns 200 and reports the outcome per-region. What must hold is that no
    # duplicate replica entry is created for that region.
    dup_resp = sm.replicate_secret_to_regions(
        SecretId=name, AddReplicaRegions=[{"Region": replica_region}]
    )
    dup_statuses = [
        r for r in dup_resp.get("ReplicationStatus", []) if r.get("Region") == replica_region
    ]
    assert dup_statuses, (
        "a duplicate ReplicateSecretToRegions must still report a per-region status"
    )

    desc_dup = sm.describe_secret(SecretId=name)
    same_region_entries = [
        r for r in desc_dup.get("ReplicationStatus", []) if r.get("Region") == replica_region
    ]
    assert len(same_region_entries) == 1, (
        f"a region must appear exactly once in ReplicationStatus, got {len(same_region_entries)}"
    )

    # a primary with live replicas cannot be deleted directly
    arn = created["ARN"]
    delete_blocked_code, delete_blocked_message = _error(lambda: sm.delete_secret(SecretId=name))
    assert delete_blocked_code == "InvalidParameterException", (
        f"deleting a primary secret with replicas must be rejected, got {delete_blocked_code}"
    )
    assert delete_blocked_message == (
        f"You can't delete secret {arn} that still has replica regions [{replica_region}]."
    ), f"deleting a primary secret with replicas returned message {delete_blocked_message!r}"
    # the rejected delete must not have scheduled deletion
    assert "DeletedDate" not in sm.describe_secret(SecretId=name), (
        "a rejected DeleteSecret must not schedule deletion on the primary"
    )

    sm.remove_regions_from_replication(
        SecretId=name, RemoveReplicaRegions=[replica_region]
    )
    desc_after = _poll_until(
        lambda: sm.describe_secret(SecretId=name),
        lambda d: replica_region
        not in {r.get("Region") for r in d.get("ReplicationStatus", [])},
        timeout_s=timeout_s,
        interval_s=3,
    )
    regions_after = {r["Region"] for r in desc_after.get("ReplicationStatus", [])}
    assert replica_region not in regions_after, (
        f"{replica_region} must not remain in ReplicationStatus after RemoveRegionsFromReplication, "
        f"got {regions_after}"
    )

    # now deletion succeeds since no replicas remain
    sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)

    def observe_state() -> str:
        try:
            described = sm.describe_secret(SecretId=name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ResourceNotFoundException":
                assert err.get("Message") == "Secrets Manager can't find the specified secret.", (
                    f"DescribeSecret on the deleted primary returned message {err.get('Message')!r}"
                )
                return "gone"
            return f"{err.get('Code')}: {err.get('Message')}"
        return "deleting" if described.get("DeletedDate") else "active"

    # ForceDeleteWithoutRecovery has no recovery window: the terminal state is gone.
    final = _poll_until(
        observe_state,
        lambda s: s == "gone",
        timeout_s=min(timeout_s, (ctx.time_left() or timeout_s) - 5),
    )
    assert final == "gone", (
        f"a force-deleted primary with no replicas must become not-found, state={final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
