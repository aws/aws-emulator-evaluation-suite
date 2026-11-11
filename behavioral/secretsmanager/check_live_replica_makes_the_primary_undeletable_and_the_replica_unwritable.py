"""live-replica-makes-the-primary-undeletable-and-the-replica-unwritable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "live-replica-makes-the-primary-undeletable-and-the-replica-unwritable"
GROUP = "replication"
SERVICES = ["secretsmanager"]

_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A live replica refuses PutSecretValue in its Region while the primary accepts the same write,
    and the primary refuses DeleteSecret until RemoveRegionsFromReplication drops the replica.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/standalone-secret.html
    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
    """
    sm = ctx.client("secretsmanager")
    replica_region = (
        _REPLICA_REGION_FALLBACK if ctx.region == _REPLICA_REGION_PRIMARY
        else _REPLICA_REGION_PRIMARY
    )
    assert replica_region != ctx.region, (
        f"the replica Region must differ from the primary's; both resolved to {ctx.region!r}"
    )
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-behav-smlinked-")
    primary_arn = sm.create_secret(
        Name=name,
        SecretString="linked-v1",
        Description="sim2real behavioral draft: the replication link as an enforced constraint",
        Tags=_sim2real_tags(),
    )["ARN"]
    ctx.on_cleanup(lambda: _reap(sm, primary_arn, ctx.region))
    # Registered after the primary's reap so it runs BEFORE it (cleanup is LIFO): the primary
    # cannot be deleted while a replica exists.
    ctx.on_cleanup(lambda: _break_link_then_reap(sm, sm_replica, primary_arn, name, replica_region))

    sm.replicate_secret_to_regions(
        SecretId=primary_arn, AddReplicaRegions=[{"Region": replica_region}]
    )
    row = _poll(
        lambda: _replication_row(sm, primary_arn, replica_region),
        lambda r: r is not None and r.get("Status") in ("InSync", "Failed"),
        timeout_s=240.0,
        interval_s=3.0,
        description=f"the {replica_region} replication row to reach a terminal status",
    )
    assert row.get("Status") == "InSync", (
        f"replication to {replica_region} must reach InSync before the constraint can be graded; "
        f"the row was {row!r}"
    )

    # Measure the propagation latency L; the absence window below is 3L with a 15s floor.
    sm.put_secret_value(SecretId=primary_arn, SecretString="linked-v2")
    started = time.monotonic()
    seen = _poll(
        lambda: _try_get(sm_replica, name),
        lambda r: r is not None and r.get("SecretString") == "linked-v2",
        timeout_s=240.0,
        interval_s=1.0,
        description=f"the primary's v2 write to reach the {replica_region} replica",
    )
    latency_s = max(time.monotonic() - started, 1.0)
    absence_s = max(3.0 * latency_s, 15.0)
    assert f":{replica_region}:" in seen["ARN"], (
        f"the replica must be a region-qualified secret in {replica_region}, not the primary read "
        f"back; its ARN is {seen['ARN']!r}"
    )

    replica_code, replica_message = _error(
        lambda: sm_replica.put_secret_value(SecretId=name, SecretString="written-at-the-replica")
    )
    assert replica_code == "InvalidParameterException", (
        f"an attached replica cannot be updated independently of its primary, so PutSecretValue in "
        f"{replica_region} must be refused with InvalidParameterException; got {replica_code!r}"
    )
    expected = "Operation not permitted on a replica secret. Call must be made in primary secret's region."
    assert replica_message == expected, f"expected {expected!r}, got {replica_message!r}"
    # Twin control: the identical write against the primary must succeed at the same moment.
    twin = sm.put_secret_value(SecretId=primary_arn, SecretString="linked-v3")
    assert twin["VersionId"], (
        f"twin control: the identical PutSecretValue against the primary must succeed at the same "
        f"moment the replica refuses it; the response was {twin!r}"
    )

    # The replica must never serve the rejected bytes over 3L; at least 5 samples even at the floor.
    samples = _sample(
        lambda: _try_get(sm_replica, name), window_s=absence_s, interval_s=min(3.0, absence_s / 7)
    )
    observed = [None if s is None else s["SecretString"] for s in samples]
    assert len(observed) >= 5, (
        f"the absence window produced only {len(observed)} samples over {absence_s:.0f}s, too few "
        f"for the assertion to mean anything"
    )
    assert "written-at-the-replica" not in observed, (
        f"the refused replica write must never become visible; over a {absence_s:.0f}s window "
        f"(3x the measured {latency_s:.1f}s propagation latency) the replica served {observed!r}"
    )
    converged = _poll(
        lambda: _try_get(sm_replica, name),
        lambda r: r is not None and r.get("SecretString") == "linked-v3",
        timeout_s=240.0,
        interval_s=3.0,
        description=(
            "the replica to converge on the primary's v3 -- the value it IS permitted to hold, "
            "proving the refusal above was scoped to the write and not a dead replication link"
        ),
    )
    assert converged["SecretString"] == "linked-v3", (
        f"the replica must serve the primary's latest value; expected 'linked-v3', got "
        f"{converged['SecretString']!r}"
    )

    delete_code, delete_message = _error(
        lambda: sm.delete_secret(SecretId=primary_arn, RecoveryWindowInDays=7)
    )
    assert delete_code == "InvalidParameterException", (
        f"a primary with a live replica must refuse DeleteSecret with InvalidParameterException until "
        f"the replica is removed; got {delete_code!r}"
    )
    expected = f"You can't delete secret {primary_arn} that still has replica regions [{replica_region}]."
    assert delete_message == expected, f"expected {expected!r}, got {delete_message!r}"
    state = sm.describe_secret(SecretId=primary_arn)
    assert "DeletedDate" not in state, (
        f"the refused delete must not schedule anything; DescribeSecret reported "
        f"DeletedDate={state.get('DeletedDate')!r}"
    )
    assert sm.get_secret_value(SecretId=primary_arn)["SecretString"] == "linked-v3", (
        "the refused delete must leave the primary fully readable"
    )
    assert [r["Region"] for r in state.get("ReplicationStatus", [])] == [replica_region], (
        f"the refused delete must leave the replication link exactly as it was; the primary now "
        f"reports {state.get('ReplicationStatus')!r}"
    )

    sm.remove_regions_from_replication(
        SecretId=primary_arn, RemoveReplicaRegions=[replica_region]
    )
    _poll(
        lambda: _replication_row(sm, primary_arn, replica_region),
        lambda r: r is None,
        timeout_s=240.0,
        interval_s=3.0,
        description=f"the primary to stop reporting {replica_region} as a replica",
    )
    scheduled = _poll(
        lambda: _delete_probe(sm, primary_arn, RecoveryWindowInDays=7),
        lambda r: r[0] == "OK",
        timeout_s=120.0,
        interval_s=3.0,
        description=(
            "the identical DeleteSecret to be accepted once the replica is gone (the removal is "
            "asynchronous, so the acceptance is polled rather than assumed instantaneous)"
        ),
    )
    assert scheduled[1] is not None, (
        f"the accepted delete must return a DeletionDate; the probe captured {scheduled[1]!r}"
    )
    after = sm.describe_secret(SecretId=primary_arn)
    assert "DeletedDate" in after, (
        f"DescribeSecret must report DeletedDate once the delete is accepted; it returned "
        f"{sorted(after)!r}"
    )
    unusable, unusable_message = _error(lambda: sm.get_secret_value(SecretId=primary_arn))
    assert unusable == "InvalidRequestException", (
        f"a secret scheduled for deletion must refuse GetSecretValue with InvalidRequestException; "
        f"got {unusable!r}"
    )
    expected = "You can't perform this operation on the secret because it was marked for deletion."
    assert unusable_message == expected, f"expected {expected!r}, got {unusable_message!r}"
    still_mutable_check, still_mutable_message = _error(
        lambda: sm.put_secret_value(SecretId=primary_arn, SecretString="after-scheduling")
    )
    assert still_mutable_check == "InvalidRequestException", (
        f"a mutation on a secret scheduled for deletion must also be refused with "
        f"InvalidRequestException; got {still_mutable_check!r}"
    )
    assert still_mutable_message == expected, f"expected {expected!r}, got {still_mutable_message!r}"
    # Undo the scheduling so teardown is a single force-delete on a live secret.
    sm.restore_secret(SecretId=primary_arn)
    revived = _poll(
        lambda: sm.describe_secret(SecretId=primary_arn),
        lambda d: "DeletedDate" not in d,
        timeout_s=60.0,
        interval_s=2.0,
        description="RestoreSecret to clear DeletedDate before teardown",
    )
    assert "DeletedDate" not in revived, (
        f"RestoreSecret must clear DeletedDate; DescribeSecret still reports "
        f"{revived.get('DeletedDate')!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _replication_row(sm, secret_id: str, region: str):
    try:
        rows = sm.describe_secret(SecretId=secret_id).get("ReplicationStatus", [])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise
    for row in rows:
        if row.get("Region") == region:
            return row
    return None


def _try_get(client, secret_id: str):
    """GetSecretValue, returning None when the secret is not there or not readable."""
    try:
        return client.get_secret_value(SecretId=secret_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in (
            "ResourceNotFoundException",
            "InvalidRequestException",
        ):
            return None
        raise


def _sample(probe, window_s: float, *, interval_s: float) -> list:
    """Observations across a whole window; a single read cannot tell 'never happened' from
    'happened and reverted'."""
    deadline = time.monotonic() + window_s
    samples = []
    while time.monotonic() < deadline:
        samples.append(probe())
        time.sleep(interval_s)
    return samples


def _error(fn):
    """The captured AWS error code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _delete_probe(client, secret_id: str, **kwargs):
    """(code_or_'OK', DeletionDate_or_None) -- one call, two observations."""
    try:
        resp = client.delete_secret(SecretId=secret_id, **kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None
    return "OK", resp.get("DeletionDate")


def _break_link_then_reap(sm, sm_replica, primary_arn: str, name: str, region: str) -> None:
    """Drop any surviving replication link, then force-delete whatever remains in the replica Region.

    The primary cannot be deleted while a replica exists.
    """
    if _replication_row(sm, primary_arn, region) is not None:
        sm.remove_regions_from_replication(SecretId=primary_arn, RemoveReplicaRegions=[region])
    _reap(sm_replica, name, region, timeout_s=90.0)


def _reap(sm_regional, secret_id: str, region: str, timeout_s: float = 120.0) -> None:
    """Force-delete one secret and poll until it is really gone; a plain DeleteSecret imposes a
    7-30 day recovery window during which the secret still bills."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm_regional.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            time.sleep(3.0)
    while time.monotonic() < deadline:
        try:
            sm_regional.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(2.0)
    raise RuntimeError(f"secret {secret_id} in {region} still present {timeout_s}s after "
        f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout, never returning its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
