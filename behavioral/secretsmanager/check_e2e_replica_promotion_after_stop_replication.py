"""e2e-replica-promotion-after-stop-replication."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "e2e-replica-promotion-after-stop-replication"
GROUP = "e2e"
SERVICES = ["secretsmanager"]

_CANDIDATE_REPLICA_REGIONS = ["us-west-2", "us-east-1", "eu-west-1"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Stopping replication to a replica region promotes it to an independent secret
    that retains the last-replicated value and is fully lifecycle-manageable on its
    own (new versions, deletion) without affecting the primary."""
    replica_region = next(r for r in _CANDIDATE_REPLICA_REGIONS if r != ctx.region)

    sm = ctx.client("secretsmanager")
    replica_sm = _cross_region_client(ctx, "secretsmanager", replica_region)

    name = ctx.unique_name("sim2real-sm-replica-")
    created = sm.create_secret(
        Name=name,
        SecretString="primary-value-v1",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    sm.replicate_secret_to_regions(SecretId=secret_arn, AddReplicaRegions=[{"Region": replica_region}])

    def _replica_status():
        d = sm.describe_secret(SecretId=secret_arn)
        for rs in d.get("ReplicationStatus", []):
            if rs["Region"] == replica_region:
                return rs
        return None

    in_sync = _poll_until(
        _replica_status,
        lambda rs: rs is not None and rs["Status"] == "InSync",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert in_sync["Status"] == "InSync", f"replica never reached InSync: {in_sync!r}"

    # update the primary's value and wait for the replica to catch up before promoting.
    sm.put_secret_value(SecretId=secret_arn, SecretString="primary-value-v2")

    # the replica secret shares the same Name but lives under the replica region's
    # endpoint; identify it by name via the replica-region client.
    _poll_until(
        lambda: replica_sm.get_secret_value(SecretId=name)["SecretString"],
        lambda v: v == "primary-value-v2",
        timeout_s=120.0,
        interval_s=5.0,
    )

    # stop replication: the replica becomes an independent, standalone secret.
    replica_sm.stop_replication_to_replica(SecretId=name)
    ctx.on_cleanup(lambda: replica_sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    # primary no longer lists the region as a replica (propagation is not necessarily
    # instantaneous, so poll rather than asserting immediately).
    primary_after = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: replica_region not in [rs["Region"] for rs in d.get("ReplicationStatus", [])],
        timeout_s=60.0,
        interval_s=5.0,
    )
    remaining_regions = [rs["Region"] for rs in primary_after.get("ReplicationStatus", [])]
    assert replica_region not in remaining_regions, (
        f"primary still lists {replica_region} as a replica after StopReplicationToReplica: "
        f"{remaining_regions!r}"
    )

    # the promoted secret retains the last-replicated value.
    promoted_value = replica_sm.get_secret_value(SecretId=name)["SecretString"]
    assert promoted_value == "primary-value-v2", (
        f"promoted secret lost the last-replicated value: got {promoted_value!r}"
    )

    # it is now independently writable: a new version on the (former) replica must
    # NOT appear on the primary, proving the two are fully decoupled. Right after promotion
    # a write on the (former) replica is not immediately visible to a same-region read (confirmed
    # on real AWS: the first read after the put still returned the pre-write value), so this reads
    # via a bounded poll rather than asserting on the very next call.
    replica_sm.put_secret_value(SecretId=name, SecretString="replica-only-value")
    replica_value = _poll_until(
        lambda: replica_sm.get_secret_value(SecretId=name)["SecretString"],
        lambda v: v == "replica-only-value",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert replica_value == "replica-only-value", f"replica did not accept its own write: {replica_value!r}"
    primary_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert primary_value == "primary-value-v2", (
        f"primary was affected by a write on the promoted (former) replica: {primary_value!r}"
    )

    # it is independently deletable without touching the primary. ForceDeleteWithoutRecovery does
    # not make DescribeSecret 404 immediately (confirmed on real AWS: the first DescribeSecret
    # right after the delete still succeeded), so gone-ness is a bounded poll, not a one-shot read.
    replica_sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)

    from botocore.exceptions import ClientError

    def _describe_deleted_replica_code():
        try:
            replica_sm.describe_secret(SecretId=name)
            return "unexpectedly-found", None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    code, message = _poll_until(
        _describe_deleted_replica_code,
        lambda c: c[0] == "ResourceNotFoundException",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert code == "ResourceNotFoundException", f"unexpected error code for a deleted secret: {code}"
    assert message == "Secrets Manager can't find the specified secret.", (
        f"unexpected error message for a deleted secret: {message!r}"
    )

    still_active_primary = sm.describe_secret(SecretId=secret_arn)
    assert still_active_primary.get("DeletedDate") is None, (
        f"primary was affected by deleting the (former) replica: {still_active_primary!r}"
    )


def _cross_region_client(ctx, service: str, region: str):
    """A client for `service` in a different region than ctx's default.

    `ctx.client(..., region=...)` keeps this on the emulator's shared endpoint (and the
    run's creds) for that arm, instead of hand-rolling `boto3.client()`, which would
    carry no `endpoint_url` and send the asserted request to real AWS even when running
    against the emulator."""
    return ctx.client(service, region=region)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception as exc:  # noqa: BLE001 - transient not-yet-replicated errors expected
            last = exc
        else:
            if predicate(last):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
