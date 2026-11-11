"""e2e-replica-secret-propagation-and-teardown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-replica-secret-propagation-and-teardown"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Replicating a secret to a region makes its value retrievable there; removing the region tears the replica down."""
    sm = ctx.client("secretsmanager")
    # Region-pinned by construction, not a hardcoded default: this check's whole point is a SECOND
    # region distinct from ctx.region, and any distinct region would do -- these two are literals
    # only because a real region name has to be spelled somehow.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-replica-secret-")
    created = sm.create_secret(
        Name=name,
        SecretString="replica-payload-v1",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = created["ARN"]

    def _cleanup():
        _tolerating_not_found(lambda: sm.remove_regions_from_replication(SecretId=arn, RemoveReplicaRegions=[replica_region]))
        _tolerating_not_found(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    ctx.on_cleanup(_cleanup)

    sm.replicate_secret_to_regions(SecretId=arn, AddReplicaRegions=[{"Region": replica_region}])

    def _replication_status():
        statuses = sm.describe_secret(SecretId=arn).get("ReplicationStatus", [])
        return next((s for s in statuses if s["Region"] == replica_region), None)

    status = _poll_until(
        _replication_status,
        lambda s: s is not None and s["Status"] in ("InSync", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert status is not None and status["Status"] == "InSync", f"replication did not reach InSync: {status}"

    replica_value = _poll_until(
        lambda: _value_or_none(lambda: sm_replica.get_secret_value(SecretId=name)),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert replica_value["SecretString"] == "replica-payload-v1", (
        f"replica in {replica_region} must serve the primary's plaintext: "
        f"{replica_value['SecretString']!r} != 'replica-payload-v1'"
    )

    sm.remove_regions_from_replication(SecretId=arn, RemoveReplicaRegions=[replica_region])

    code, message = _poll_until(
        lambda: _outcome(lambda: sm_replica.get_secret_value(SecretId=name)),
        lambda got: got[0] == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert code == "ResourceNotFoundException", (
        f"replica must be gone from {replica_region} after RemoveRegionsFromReplication, "
        f"got error code {code!r}"
    )
    assert message == "Secrets Manager can't find the specified secret.", (
        f"GetSecretValue on the removed replica returned message {message!r}"
    )

    remaining = sm.describe_secret(SecretId=arn).get("ReplicationStatus", [])
    assert all(s["Region"] != replica_region for s in remaining), (
        f"primary must stop listing {replica_region} in ReplicationStatus after removal, "
        f"got {remaining!r}"
    )


def _tolerating_not_found(fn) -> None:
    """Teardown: run fn; a resource that is already gone is fine, any other error raises."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# What _outcome reports for a call that succeeded: a pair no AWS error can equal.
_SUCCEEDED = ("<call succeeded>", "<call succeeded>")


def _outcome(fn):
    """The (code, message) fn raised, or _SUCCEEDED when it succeeded."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return _SUCCEEDED


def _value_or_none(fn):
    try:
        return fn()
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
