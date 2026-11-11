"""replicate-secret-refuses-a-name-collision-until-force-overwrite."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicate-secret-refuses-a-name-collision-until-force-overwrite"
GROUP = "replication"
SERVICES = ["secretsmanager"]

_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"

# The exact StatusMessage wording is undocumented, so the assertion is "non-empty AND mentions
# one of these", which still fails a generic "Failed" with no explanation.
_COLLISION_HINTS = ("already exists", "same name", "name")


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
    """Replicating into a Region that already holds a same-named secret settles to Failed and leaves
    that secret untouched; the same call with ForceOverwriteReplicaSecret=True reaches InSync,
    overwrites it with the primary's plaintext, and later primary writes propagate.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ReplicateSecretToRegions.html
    """
    sm = ctx.client("secretsmanager")
    replica_region = (
        _REPLICA_REGION_FALLBACK if ctx.region == _REPLICA_REGION_PRIMARY
        else _REPLICA_REGION_PRIMARY
    )
    assert replica_region != ctx.region, (
        f"the destination Region must differ from the primary's; both resolved to {ctx.region!r}"
    )
    sm_dest = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-behav-smcollide-")

    # A standalone secret of the same name, created in the destination first.
    squatter_arn = sm_dest.create_secret(
        Name=name,
        SecretString="squatter-value",
        Description="sim2real behavioral draft: replica name-collision squatter",
        Tags=_sim2real_tags(),
    )["ARN"]
    # Reaped by name as well as ARN: the forced overwrite may not preserve the squatter's ARN.
    # Cleanup is LIFO, so the name-scoped reap runs last.
    ctx.on_cleanup(lambda: _reap(sm_dest, name, replica_region))
    ctx.on_cleanup(lambda: _reap(sm_dest, squatter_arn, replica_region))
    assert f":{replica_region}:" in squatter_arn, (
        f"the squatter must live in {replica_region}; its ARN is {squatter_arn!r}"
    )

    primary_arn = sm.create_secret(
        Name=name,
        SecretString="primary-value",
        Description="sim2real behavioral draft: replica name-collision primary",
        Tags=_sim2real_tags(),
    )["ARN"]
    # Cleanup is LIFO, so the link-breaker runs first: a primary with a live replica refuses
    # deletion.
    ctx.on_cleanup(lambda: _reap(sm, primary_arn, ctx.region))
    ctx.on_cleanup(lambda: _break_link(sm, primary_arn, replica_region))
    assert primary_arn != squatter_arn, (
        f"the primary and the squatter must be distinct secrets; both ARNs are {primary_arn!r}"
    )

    unforced = _replicate(sm, primary_arn, replica_region, force=False)
    assert unforced["outcome"] == "Failed", (
        f"replicating into {replica_region}, which already holds a standalone secret named {name!r}, "
        f"must not succeed while ForceOverwriteReplicaSecret is unset; ReplicateSecretToRegions "
        f"reported outcome={unforced['outcome']!r} detail={unforced['detail']!r}"
    )
    message = (unforced["detail"] or "")
    assert message, (
        f"the Failed replication row must explain itself; StatusMessage was {message!r} for "
        f"{replica_region}"
    )
    assert any(hint in message.lower() for hint in _COLLISION_HINTS), (
        f"the Failed replication row must name the name-collision as the cause; expected one of "
        f"{_COLLISION_HINTS!r} in the StatusMessage, got {message!r}"
    )

    # A single late read cannot distinguish "never overwritten" from "overwritten and reverted", so
    # five consecutive destination reads must all still be the squatter's own bytes and ARN.
    samples = _sample(lambda: _try_get(sm_dest, name), count=5, interval_s=3.0)
    assert all(s is not None for s in samples), (
        f"the refused replication must leave the pre-existing {replica_region} secret intact; one "
        f"or more of five consecutive destination reads found nothing: {samples!r}"
    )
    assert all(s["SecretString"] == "squatter-value" for s in samples), (
        f"the refused replication must not have overwritten the destination's plaintext; five "
        f"consecutive reads returned {[s['SecretString'] for s in samples]!r}, expected every one "
        f"to be 'squatter-value'"
    )
    assert all(s["ARN"] == squatter_arn for s in samples), (
        f"the destination secret must still be the SAME secret, not a replacement wearing its name; "
        f"expected {squatter_arn!r}, reads returned {[s['ARN'] for s in samples]!r}"
    )
    assert sm.get_secret_value(SecretId=primary_arn)["SecretString"] == "primary-value", (
        "a failed replication must leave the primary readable and unchanged"
    )

    # Clear the Failed row before the forced retry; harmless if AWS does not require it.
    _break_link(sm, primary_arn, replica_region)
    forced = _replicate(sm, primary_arn, replica_region, force=True)
    assert forced["outcome"] == "InSync", (
        f"the identical replication with ForceOverwriteReplicaSecret=True must be accepted and reach "
        f"InSync; got outcome={forced['outcome']!r} detail={forced['detail']!r}"
    )

    # Polled because replication is asynchronous.
    overwritten = _poll(
        lambda: _try_get(sm_dest, name),
        lambda r: r is not None and r.get("SecretString") == "primary-value",
        timeout_s=240.0,
        interval_s=3.0,
        description=(
            f"the forced replication to overwrite the {replica_region} secret with the primary's "
            f"plaintext"
        ),
    )
    assert overwritten["SecretString"] == "primary-value", (
        f"after ForceOverwriteReplicaSecret=True the destination must serve the PRIMARY's bytes; "
        f"expected 'primary-value', got {overwritten['SecretString']!r}"
    )
    assert f":{replica_region}:" in overwritten["ARN"], (
        f"the overwritten replica must remain region-qualified to {replica_region}; its ARN is "
        f"{overwritten['ARN']!r}"
    )
    # The ARN suffix (primary's or squatter's) is not asserted: the docs do not settle it.
    # The primary owns the destination: it reports the link and its writes propagate.
    linked = _replication_row(sm, primary_arn, replica_region)
    assert linked is not None and linked.get("Status") == "InSync", (
        f"the primary must report {replica_region} as an InSync replica after the forced "
        f"replication; DescribeSecret's row was {linked!r}"
    )
    sm.put_secret_value(SecretId=primary_arn, SecretString="primary-value-v2")
    propagated = _poll(
        lambda: _try_get(sm_dest, name),
        lambda r: r is not None and r.get("SecretString") == "primary-value-v2",
        timeout_s=240.0,
        interval_s=3.0,
        description=(
            f"a primary write to reach the overwritten {replica_region} replica, proving the forced "
            f"overwrite produced a real replication link and not a one-shot copy"
        ),
    )
    assert propagated["SecretString"] == "primary-value-v2", (
        f"the overwritten destination must track subsequent primary writes; expected "
        f"'primary-value-v2', got {propagated['SecretString']!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _replicate(sm, primary_arn: str, region: str, *, force: bool) -> dict:
    """Replicate and settle to a terminal per-Region status.

    Returns {"outcome": "InSync"|"Failed"|<error code>, "detail": StatusMessage or error message},
    keeping an API-level refusal distinct from a Failed status row.
    """
    kwargs = {"SecretId": primary_arn, "AddReplicaRegions": [{"Region": region}]}
    if force:
        kwargs["ForceOverwriteReplicaSecret"] = True
    try:
        sm.replicate_secret_to_regions(**kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"outcome": err.get("Code"), "detail": err.get("Message")}
    row = _poll(
        lambda: _replication_row(sm, primary_arn, region),
        lambda r: r is not None and r.get("Status") in ("InSync", "Failed"),
        timeout_s=240.0,
        interval_s=3.0,
        description=(
            f"the {region} ReplicationStatus row to reach a terminal status "
            f"(force={force}); InProgress is transient and must not be asserted against"
        ),
    )
    return {"outcome": row.get("Status"), "detail": row.get("StatusMessage")}


def _replication_row(sm, secret_id: str, region: str):
    for row in sm.describe_secret(SecretId=secret_id).get("ReplicationStatus", []):
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


def _sample(probe, *, count: int, interval_s: float) -> list:
    """N consecutive observations spaced interval_s apart."""
    samples = []
    for i in range(count):
        samples.append(probe())
        if i + 1 < count:
            time.sleep(interval_s)
    return samples


def _break_link(sm, primary_arn: str, region: str) -> None:
    """Drop the replica link, live or Failed, so the primary becomes deletable; a primary that is
    already gone, reports no row for the Region, or refuses to drop a Failed row has nothing to drop."""
    try:
        row = _replication_row(sm, primary_arn, region)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    if row is not None:
        try:
            sm.remove_regions_from_replication(
                SecretId=primary_arn, RemoveReplicaRegions=[region]
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidRequestException" and row.get("Status") == "Failed":
                return
            raise


def _reap(sm_regional, secret_arn: str, region: str, timeout_s: float = 120.0) -> None:
    """Force-delete one secret and poll until it is really gone; a plain DeleteSecret imposes a
    7-30 day recovery window during which the secret still bills."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm_regional.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            time.sleep(3.0)
    while time.monotonic() < deadline:
        try:
            sm_regional.describe_secret(SecretId=secret_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(2.0)
    raise RuntimeError(f"secret {secret_arn} in {region} still present {timeout_s}s after "
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
