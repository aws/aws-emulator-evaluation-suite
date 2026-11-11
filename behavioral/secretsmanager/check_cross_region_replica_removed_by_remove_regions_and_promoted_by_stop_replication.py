"""cross-region-replica-removed-by-remove-regions-and-promoted-by-stop-replication."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-region-replica-removed-by-remove-regions-and-promoted-by-stop-replication"

GROUP = "replication"

SERVICES = ["secretsmanager"]

_SCENARIO = "secretsmanager-cross-region-replica"

# A fixed replica region, so any residue lands where this check's cleanup deletes it.
_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"
#: Retry window for a replica that refuses deletion until its detach lands; both replica and
#: both primary teardowns fit the 900 s cleanup budget.
_REPLICA_DELETE_TIMEOUT_S = 300.0


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RemoveRegionsFromReplication on the primary deletes the replica, while
    StopReplicationToReplica from the replica Region promotes it to a standalone secret that keeps
    its value and stops tracking primary writes.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/stop-replication.html
    """
    sm = ctx.client("secretsmanager")
    replica_region = (
        _REPLICA_REGION_FALLBACK if ctx.region == _REPLICA_REGION_PRIMARY else _REPLICA_REGION_PRIMARY
    )
    assert replica_region != ctx.region, (
        f"the replica region must differ from the primary; both resolved to {ctx.region!r}"
    )
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    v1, v2, v3, v4 = (
        "replicated-credential-v1",
        "replicated-credential-v2",
        "replicated-credential-v3",
        "replicated-credential-v4",
    )

    name = ctx.unique_name("sim2real-behav-replica-")
    created = sm.create_secret(
        Name=name,
        SecretString=v1,
        Description="sim2real behavioral check: cross-region replica removal vs promotion",
        Tags=_sim2real_tags(_SCENARIO),
    )
    primary_arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, primary_arn))
    # Cleanup is LIFO, so this runs before the primary reap: a secret with a live replica refuses
    # deletion.
    ctx.on_cleanup(lambda: _detach_and_reap_replica(ctx, primary_arn, name, replica_region))

    # --- replicate, and prove the replica is a real secret holding the real plaintext -----------
    _replicate_and_wait(ctx, sm, primary_arn, replica_region)

    replica_v1 = _poll_until(
        ctx,
        lambda: _try_get(sm_replica, name),
        lambda r: r is not None and r.get("SecretString") == v1,
        timeout_s=180.0,
        interval_s=2.0,
        description=f"the {replica_region} replica to serve the primary plaintext v1",
    )
    assert replica_v1["SecretString"] == v1, (
        f"the replica does not serve the primary plaintext: {replica_v1['SecretString']!r} != {v1!r}"
    )
    assert replica_v1["ARN"] != primary_arn and f":{replica_region}:" in replica_v1["ARN"], (
        f"the replica must be a distinct, region-qualified ARN, not the primary's: "
        f"{replica_v1['ARN']!r} (primary {primary_arn!r})"
    )

    # --- a primary write propagates ------------------------------------------------------------
    sm.put_secret_value(SecretId=primary_arn, SecretString=v2)
    replica_v2 = _poll_until(
        ctx,
        lambda: _try_get(sm_replica, name),
        lambda r: r is not None and r.get("SecretString") == v2,
        timeout_s=180.0,
        interval_s=1.0,
        description=f"the primary's v2 write to propagate to the {replica_region} replica",
    )
    assert replica_v2["SecretString"] == v2, (
        f"a primary update did not propagate to the replica: {replica_v2['SecretString']!r} != {v2!r}"
    )

    # --- detach #1: RemoveRegionsFromReplication DELETES the replica ---------------------------
    sm.remove_regions_from_replication(SecretId=primary_arn, RemoveReplicaRegions=[replica_region])
    after_remove = _poll_until(
        ctx,
        lambda: sm.describe_secret(SecretId=primary_arn),
        lambda d: replica_region not in [r["Region"] for r in d.get("ReplicationStatus", [])],
        timeout_s=180.0,
        interval_s=2.0,
        description=f"the primary to stop listing {replica_region} in ReplicationStatus",
    )
    assert replica_region not in [r["Region"] for r in after_remove.get("ReplicationStatus", [])], (
        f"the primary still lists the removed region: {after_remove.get('ReplicationStatus')!r}"
    )
    _poll_until(
        ctx,
        lambda: _try_get(sm_replica, name),
        lambda r: r is None,
        timeout_s=180.0,
        interval_s=2.0,
        description=(
            f"the {replica_region} replica to disappear after RemoveRegionsFromReplication "
            f"(MEASURED: this API deletes the replica, it does not promote it)"
        ),
    )
    # The primary is untouched by its replica's removal.
    sm.put_secret_value(SecretId=primary_arn, SecretString=v3)
    primary_v3 = sm.get_secret_value(SecretId=primary_arn)
    assert primary_v3["SecretString"] == v3, (
        f"the primary must still accept and serve writes after its replica was removed: "
        f"{primary_v3['SecretString']!r} != {v3!r}"
    )
    # Read after the primary's later write: a replica that survived the removal would be served here.
    lingering = _try_get(sm_replica, name)
    assert lingering is None, (
        f"RemoveRegionsFromReplication must leave NOTHING behind in {replica_region}: after the "
        f"primary's v3 write the replica-region read returned {lingering!r}"
    )

    # --- detach #2: StopReplicationToReplica PROMOTES the replica -------------------------------
    # Re-replicate. A fresh replica must be seeded with the primary's CURRENT value (v3), not with
    # the value it held in its previous life (v2) -- which also proves the first replica really was
    # destroyed rather than resurrected.
    _replicate_and_wait(ctx, sm, primary_arn, replica_region)
    replica_v3 = _poll_until(
        ctx,
        lambda: _try_get(sm_replica, name),
        lambda r: r is not None and r.get("SecretString") == v3,
        timeout_s=180.0,
        interval_s=2.0,
        description=f"the re-created {replica_region} replica to be seeded with the primary's v3",
    )
    assert replica_v3["SecretString"] == v3, (
        f"a re-created replica must be seeded with the primary's CURRENT value, not a stale one: "
        f"{replica_v3['SecretString']!r} != {v3!r}"
    )

    # This call MUST be issued from the replica's own Region -- that is the whole distinction being
    # graded, and it is unobservable from the primary's endpoint.
    sm_replica.stop_replication_to_replica(SecretId=name)
    after_stop = _poll_until(
        ctx,
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
        f"StopReplicationToReplica must PROMOTE the replica to a standalone secret in "
        f"{replica_region}; instead it is no longer readable there -- which would make it behave "
        f"like RemoveRegionsFromReplication, the distinction this check exists to grade"
    )
    assert promoted["SecretString"] == v3, (
        f"the promoted secret must keep the plaintext it held at promotion: "
        f"{promoted['SecretString']!r} != {v3!r}"
    )

    # --- the promoted secret stops tracking -----------------------------------------------------
    # A twin secret still replicated to the same region is the contrast: once the same write has
    # reached the twin's replica, it would have reached a promoted secret that still tracked.
    twin_name = ctx.unique_name("sim2real-behav-replica-twin-")
    twin_arn = sm.create_secret(
        Name=twin_name,
        SecretString=v3,
        Description="sim2real behavioral check: replicated twin of the promoted secret",
        Tags=_sim2real_tags(_SCENARIO),
    )["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, twin_arn))
    ctx.on_cleanup(lambda: _detach_and_reap_replica(ctx, twin_arn, twin_name, replica_region))
    _replicate_and_wait(ctx, sm, twin_arn, replica_region)

    sm.put_secret_value(SecretId=primary_arn, SecretString=v4)
    sm.put_secret_value(SecretId=twin_arn, SecretString=v4)
    _poll_until(
        ctx,
        lambda: _try_get(sm_replica, twin_name),
        lambda r: r is not None and r.get("SecretString") == v4,
        timeout_s=180.0,
        interval_s=2.0,
        description=f"the twin's v4 write to propagate to its {replica_region} replica",
    )
    after = _try_get(sm_replica, name)
    observed = None if after is None else after["SecretString"]
    assert observed == v3, (
        f"a promoted, detached secret must NOT track further primary writes; once the same v4 write "
        f"reached the still-replicated twin, the promoted secret served {observed!r}, expected {v3!r}"
    )
    primary_v4 = sm.get_secret_value(SecretId=primary_arn)
    assert primary_v4["SecretString"] == v4, (
        f"control: the primary did receive the write the promoted secret must not have seen, so the "
        f"non-convergence above is not simply a failed write: {primary_v4['SecretString']!r} != {v4!r}"
    )


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _poll_until(
    ctx, probe, predicate, *, timeout_s, interval_s, description, fail_fast=None, fail_message=""
):
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 10.0))
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if fail_fast is not None and fail_fast(last):
            raise AssertionError(f"{fail_message}: {last!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s:.0f}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _replicate_and_wait(ctx, sm, primary_arn: str, replica_region: str) -> None:
    resp = sm.replicate_secret_to_regions(
        SecretId=primary_arn, AddReplicaRegions=[{"Region": replica_region}]
    )
    failed = [
        r
        for r in resp.get("ReplicationStatus", [])
        if r.get("Region") == replica_region and r.get("Status") == "Failed"
    ]
    assert not failed, f"ReplicateSecretToRegions reported Failed immediately: {failed!r}"
    _poll_until(
        ctx,
        lambda: _replication_status(sm, primary_arn, replica_region),
        lambda st: st is not None and st.get("Status") == "InSync",
        timeout_s=180.0,
        interval_s=2.0,
        description=f"the {replica_region} replica to report Status=InSync",
        fail_fast=lambda st: st is not None and st.get("Status") == "Failed",
        fail_message=f"replication to {replica_region} entered Failed",
    )


def _replication_status(sm, secret_id: str, region: str):
    for row in sm.describe_secret(SecretId=secret_id).get("ReplicationStatus", []):
        if row["Region"] == region:
            return row
    return None


def _try_get(client, secret_id: str):
    """GetSecretValue, returning None if the secret is not (yet, or any longer) there. Used as a poll
    probe, so a ResourceNotFoundException is an observation rather than a failure."""
    try:
        return client.get_secret_value(SecretId=secret_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in (
            "ResourceNotFoundException",
            "InvalidRequestException",
        ):
            return None
        raise


def _detach_and_reap_replica(ctx, primary_arn: str, name: str, replica_region: str) -> None:
    """Break any surviving replication link, then force-delete whatever is left in the replica region.

    The primary cannot be deleted while a replica exists.
    """
    sm = ctx.client("secretsmanager")
    replica_client = ctx.client("secretsmanager", region=replica_region)
    try:
        sm.remove_regions_from_replication(
            SecretId=primary_arn, RemoveReplicaRegions=[replica_region]
        )
    except ClientError as exc:
        # Gone primary, or a region that is not a replica: nothing to detach.
        if exc.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException",
            "InvalidParameterException",
            "InvalidRequestException",
        ):
            raise
    # Whatever remains in the replica region is either a promoted standalone secret or nothing.
    # The detach is asynchronous: a replica refuses deletion until it lands.
    deadline = time.monotonic() + _REPLICA_DELETE_TIMEOUT_S
    while True:
        try:
            replica_client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            still_replica = code == "InvalidParameterException" and exc.response["Error"].get(
                "Message", ""
            ).startswith("Operation not permitted on a replica secret")
            if (code != "InvalidRequestException" and not still_replica) or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _reap_secret(ctx, secret_id: str, timeout_s: float = 120.0) -> None:
    """Force-delete a secret and poll until it is really gone.

    A plain DeleteSecret imposes a 7-30 day recovery window, so the secret would outlive the run.
    """
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            # A secret that still has a replica refuses deletion; the detach above is asynchronous.
            time.sleep(3.0)
            continue
    while time.monotonic() < deadline:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(2.0)
    raise RuntimeError(f"secret {secret_id} still present {timeout_s}s after "
        f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
