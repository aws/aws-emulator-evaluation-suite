"""replica-under-a-missing-kms-key-reports-failed-and-is-recoverable-by-remove-then-replicate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replica-under-a-missing-kms-key-reports-failed-and-is-recoverable-by-remove-then-replicate"
GROUP = "replication"
SERVICES = ["secretsmanager"]

_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Replicating under a KMS alias missing in the replica Region settles to Failed with a KMS
    NotFoundException StatusMessage and no readable replica; RemoveRegionsFromReplication clears it
    and replicating again under the default key reaches InSync and serves the plaintext.
    """
    sm = ctx.client("secretsmanager")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    replica_region = (
        _REPLICA_REGION_FALLBACK if ctx.region == _REPLICA_REGION_PRIMARY else _REPLICA_REGION_PRIMARY
    )
    assert replica_region != ctx.region, f"replica and primary both resolved to {ctx.region!r}"
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-behav-replfail-")
    created = sm.create_secret(
        Name=name, SecretString="replicated-plaintext", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    primary_arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_primary(sm, primary_arn))
    ctx.on_cleanup(lambda: _detach_and_reap_replica(sm, sm_replica, primary_arn, name, replica_region))

    missing_alias = "alias/" + ctx.unique_name("sim2real-behav-nokey-")
    sm.replicate_secret_to_regions(
        SecretId=primary_arn,
        AddReplicaRegions=[{"Region": replica_region, "KmsKeyId": missing_alias}],
    )
    failed = _poll(
        lambda: _status(sm, primary_arn, replica_region),
        lambda st: st is not None and st.get("Status") != "InProgress",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"the {replica_region} replica under a missing key to settle",
    )
    assert failed.get("Status") == "Failed", (
        f"a replica under a nonexistent key must settle to Failed; got {failed!r}"
    )
    assert failed.get("KmsKeyId") == missing_alias, (
        f"the failed row must name the requested key; got {failed.get('KmsKeyId')!r}"
    )
    # The message ends in the KMS client's diagnostic suffix, which carries a per-request id; the
    # part before it is graded exactly, built from the account, Region and alias this check chose.
    reason, _, diagnostics = failed.get("StatusMessage", "").partition(" (Service: AWSKMS;")
    expected_reason = (
        "Replication failed: Secrets Manager can't encrypt the secret value: Alias "
        f"arn:aws:kms:{replica_region}:{account_id}:{missing_alias} is not found."
    )
    assert reason == expected_reason, f"failed StatusMessage reason {reason!r} != {expected_reason!r}"
    assert " Error Code: NotFoundException;" in diagnostics, (
        f"the failure must be KMS NotFoundException; diagnostics were {diagnostics!r}"
    )
    absent = _get_code(sm_replica, name)
    assert absent == ("ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
        f"a Failed replica must not be readable in {replica_region}; got {absent!r}"
    )

    sm.remove_regions_from_replication(SecretId=primary_arn, RemoveReplicaRegions=[replica_region])
    cleared = _poll(
        lambda: _status(sm, primary_arn, replica_region),
        lambda st: st is None,
        timeout_s=120.0,
        interval_s=3.0,
        description="RemoveRegionsFromReplication to clear the failed entry",
    )
    assert cleared is None, f"the failed region entry must be gone; got {cleared!r}"

    sm.replicate_secret_to_regions(SecretId=primary_arn, AddReplicaRegions=[{"Region": replica_region}])
    synced = _poll(
        lambda: _status(sm, primary_arn, replica_region),
        lambda st: st is not None and st.get("Status") != "InProgress",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"the retried {replica_region} replica to settle",
    )
    assert synced.get("Status") == "InSync", f"the retried replica must reach InSync; got {synced!r}"
    served = _poll(
        lambda: _get_code(sm_replica, name),
        lambda r: r[0] == "ok",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"the {replica_region} replica to serve the plaintext",
    )
    assert served == ("ok", "replicated-plaintext"), (
        f"the recovered replica must serve the primary's plaintext; got {served!r}"
    )


def _status(sm, secret_id, region):
    for row in sm.describe_secret(SecretId=secret_id).get("ReplicationStatus", []):
        if row["Region"] == region:
            return row
    return None


def _get_code(client, secret_id):
    try:
        return ("ok", client.get_secret_value(SecretId=secret_id)["SecretString"])
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _detach_and_reap_replica(sm, sm_replica, primary_arn, name, region):
    """Break any surviving link, then force-delete whatever remains in the replica Region."""
    try:
        sm.remove_regions_from_replication(SecretId=primary_arn, RemoveReplicaRegions=[region])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "InvalidParameterException",
            "InvalidRequestException",
        ):
            raise
    deadline = time.monotonic() + 120.0
    while True:
        try:
            sm_replica.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"replica-region secret {name} in {region} could not be deleted: {exc}")
            time.sleep(3.0)
            continue
        return


def _reap_primary(sm, primary_arn):
    deadline = time.monotonic() + 120.0
    while True:
        try:
            sm.delete_secret(SecretId=primary_arn, ForceDeleteWithoutRecovery=True)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
