"""server-side-replication-propagates-value-without-client-action."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "server-side-replication-propagates-value-without-client-action"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReplicateSecretToRegions reaches InSync and the replica Region returns the same plaintext
    for the secret's name, with no write ever issued in that Region by the client."""
    sm = ctx.client("secretsmanager")
    # Any region other than ctx.region works as the replica.
    _candidate_regions = ["us-west-2", "us-east-1", "eu-west-1"]
    replica_region = next(r for r in _candidate_regions if r != ctx.region)
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-behav-smrepl-")
    original_value = "replicate-me-v1"
    primary = sm.create_secret(
        Name=name,
        SecretString=original_value,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    primary_arn = primary["ARN"]

    def _cleanup():
        _error_code(
            lambda: sm.remove_regions_from_replication(
                SecretId=primary_arn, RemoveReplicaRegions=[replica_region]
            )
        )
        sm.delete_secret(SecretId=primary_arn, ForceDeleteWithoutRecovery=True)

    ctx.on_cleanup(_cleanup)

    sm.replicate_secret_to_regions(
        SecretId=primary_arn, AddReplicaRegions=[{"Region": replica_region}]
    )

    description = _poll_until(
        lambda: sm.describe_secret(SecretId=primary_arn),
        lambda d: any(
            r["Region"] == replica_region and r["Status"] in ("InSync", "Failed")
            for r in d.get("ReplicationStatus", [])
        ),
        timeout_s=120.0,
        interval_s=5.0,
    )
    replica_status = next(
        r for r in description["ReplicationStatus"] if r["Region"] == replica_region
    )
    assert replica_status["Status"] == "InSync", replica_status

    replica_value = sm_replica.get_secret_value(SecretId=name)["SecretString"]
    assert replica_value == original_value, (
        f"replica secret value mismatch: expected {original_value!r}, got {replica_value!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
