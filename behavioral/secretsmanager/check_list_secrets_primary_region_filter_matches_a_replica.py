"""list-secrets-primary-region-filter-matches-a-replica."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-secrets-primary-region-filter-matches-a-replica"
GROUP = "cross-region"
SERVICES = ["secretsmanager"]


def _second_region(region: str) -> str:
    """A second commercial region every account has enabled, distinct from ``region``."""
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _drop_replica_then_delete(sm, primary_name: str, sm_replica, replica_region: str):
    """Remove a replica region, wait for the removal to clear, then delete the primary.

    A primary cannot be deleted while a replica is still listed, so the removal is awaited
    here rather than left to a later, separate teardown.
    """

    def undo() -> None:
        try:
            sm.remove_regions_from_replication(
                SecretId=primary_name, RemoveReplicaRegions=[replica_region]
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            return
        deadline = time.monotonic() + 40.0
        while True:
            try:
                desc = sm.describe_secret(SecretId=primary_name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    break
                raise
            regions = {r.get("Region") for r in desc.get("ReplicationStatus", [])}
            if replica_region not in regions:
                break
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{replica_region} still listed in ReplicationStatus 40s after removal"
                )
            time.sleep(2.0)
        _force_delete(sm, primary_name)

    return undo


def _poll(probe, ok, *, timeout_s=120.0, interval_s=3.0):
    """The last observation of ``probe()`` once ``ok`` holds, else at the deadline."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not ok(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecrets filtered by primary-region matches both a replicated secret and its
    replica by the primary's region, and matches neither region for an unreplicated secret.
    """
    home = ctx.region
    away = _second_region(home)
    sm = ctx.client("secretsmanager")
    sm_away = ctx.client("secretsmanager", region=away)

    base = ctx.unique_name("sim2real-behav-lspr-")
    primary_name = base + "-primary"
    standalone_name = base + "-standalone"

    sm.create_secret(Name=primary_name, SecretString="sim2real-not-a-real-secret")
    ctx.on_cleanup(lambda: _force_delete(sm, primary_name))

    sm_away.create_secret(Name=standalone_name, SecretString="sim2real-not-a-real-secret")
    ctx.on_cleanup(lambda: _force_delete(sm_away, standalone_name))

    sm.replicate_secret_to_regions(
        SecretId=primary_name, AddReplicaRegions=[{"Region": away}]
    )
    ctx.on_cleanup(_drop_replica_then_delete(sm, primary_name, sm_away, away))

    settled = _poll(
        lambda: sm.describe_secret(SecretId=primary_name),
        lambda d: any(
            r.get("Region") == away and r.get("Status") in ("InSync", "Failed")
            for r in d.get("ReplicationStatus", [])
        ),
    )
    replica_status = [r for r in settled.get("ReplicationStatus", []) if r.get("Region") == away]
    assert replica_status and replica_status[0].get("Status") == "InSync", (
        f"replication to {away} did not reach InSync: {replica_status}"
    )

    own_filter = [{"Key": "name", "Values": [base]}]

    def _names(sm_client, extra_filter):
        return [
            s["Name"]
            for page in sm_client.get_paginator("list_secrets").paginate(
                Filters=[*own_filter, extra_filter]
            )
            for s in page["SecretList"]
        ]

    by_home_primary_in_away = _poll(
        lambda: _names(sm_away, {"Key": "primary-region", "Values": [home]}),
        lambda got: got == [primary_name],
    )
    assert by_home_primary_in_away == [primary_name], (
        f"primary-region={home!r} in {away} must list only the replica {primary_name!r}, "
        f"got {by_home_primary_in_away}"
    )

    by_home_primary_in_home = _names(sm, {"Key": "primary-region", "Values": [home]})
    assert by_home_primary_in_home == [primary_name], (
        f"primary-region={home!r} in {home} must list the primary {primary_name!r} too, "
        f"got {by_home_primary_in_home}"
    )

    # The standalone secret never took part in replication, so it carries no PrimaryRegion
    # at all and must not surface under either region's filter value.
    by_away_primary = _names(sm_away, {"Key": "primary-region", "Values": [away]})
    assert by_away_primary == [], (
        f"primary-region={away!r} in {away} must not match the unreplicated standalone "
        f"secret {standalone_name!r}, got {by_away_primary}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
