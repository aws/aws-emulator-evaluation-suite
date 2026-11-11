"""update-primary-region-non-multiregion-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-primary-region-non-multiregion-key-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]

_CANDIDATE_REGIONS = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-southeast-1"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion on a single-Region key fails (UnsupportedOperationException) and leaves
    it unchanged; on a multi-Region primary with a replica there it swaps PRIMARY/REPLICA roles."""
    primary_region = ctx.region
    (replica_region,) = _pick_regions(primary_region, 1)
    kms = ctx.client("kms")

    plain = kms.create_key(
        Description=ctx.unique_name("sim2real-non-mrk-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    plain_key_id = plain["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, plain_key_id))
    assert plain["KeyMetadata"]["MultiRegion"] is False, (
        f"expected a freshly created key with no MultiRegion=True to report MultiRegion=False, "
        f"got {plain['KeyMetadata']['MultiRegion']!r}"
    )

    err = _error(
        lambda: kms.update_primary_region(KeyId=plain_key_id, PrimaryRegion=replica_region)
    )
    assert err["Code"] == "UnsupportedOperationException", (
        f"expected UpdatePrimaryRegion on a non-multi-Region key to fail with "
        f"UnsupportedOperationException, got {err!r}"
    )
    assert err["Message"] == f"{plain['KeyMetadata']['Arn']} is not a multi-region key.", err

    # effect-absent: the key is still a plain single-region key, unaffected by the rejected call
    unaffected = kms.describe_key(KeyId=plain_key_id)["KeyMetadata"]
    assert unaffected["MultiRegion"] is False, (
        f"expected the rejected UpdatePrimaryRegion call to leave MultiRegion=False, "
        f"got {unaffected['MultiRegion']!r}"
    )
    assert "MultiRegionConfiguration" not in unaffected, (
        f"expected no MultiRegionConfiguration on an unaffected non-multi-Region key, "
        f"got {unaffected.get('MultiRegionConfiguration')!r}"
    )
    assert unaffected["KeyState"] == "Enabled", (
        f"expected the key to remain Enabled after the rejected call, "
        f"got {unaffected['KeyState']!r}"
    )

    # positive control: the same operation shape succeeds against an actual multi-Region primary
    # key that already has a replica in the target region
    replica_kms = ctx.client("kms", region=replica_region)

    mrk = kms.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-mrk-swap-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    mrk_key_id = mrk["KeyMetadata"]["KeyId"]

    def _cleanup_mrk() -> None:
        for client in (kms, replica_kms):
            _best_effort_schedule_deletion(client, mrk_key_id)

    ctx.on_cleanup(_cleanup_mrk)

    kms.replicate_key(KeyId=mrk_key_id, ReplicaRegion=replica_region)
    _poll_until(
        lambda: kms.describe_key(KeyId=mrk_key_id)["KeyMetadata"],
        lambda m: any(
            r["Region"] == replica_region for r in m["MultiRegionConfiguration"]["ReplicaKeys"]
        ),
        timeout_s=120,
        interval_s=5,
    )

    # the replica can stay transiently un-promotable (KMSInvalidStateException) for a short
    # window after ReplicateKey returns; retry the REAL operation itself rather than a separate
    # cross-region visibility probe, which can lag independently by minutes.
    _retry_until_success(
        lambda: kms.update_primary_region(KeyId=mrk_key_id, PrimaryRegion=replica_region),
        timeout_s=120,
        interval_s=5,
    )
    swapped = _poll_until(
        lambda: kms.describe_key(KeyId=mrk_key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled"
        and m["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=90,
        interval_s=5,
    )
    assert swapped["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == replica_region, (
        f"expected UpdatePrimaryRegion on a genuine multi-Region primary with a replica in "
        f"{replica_region!r} to swap the primary role there, "
        f"got PrimaryKey.Region={swapped['MultiRegionConfiguration']['PrimaryKey']['Region']!r}"
    )



def _pick_regions(exclude_region, n):
    picked = [r for r in _CANDIDATE_REGIONS if r != exclude_region][:n]
    if len(picked) < n:
        raise AssertionError("not enough candidate regions distinct from ctx.region")
    return picked


def _error(fn):
    """The error (Code and Message) of a refused call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response["Error"]
        return {"Code": e.get("Code"), "Message": e.get("Message")}
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            # the replica key can be transiently invisible (NotFoundException) or not yet
            # usable (KMSInvalidStateException) in its own region right after ReplicateKey
            last_exc = exc
            time.sleep(interval_s)
            continue
        if predicate(last):
            return last
        time.sleep(interval_s)
    if last is None and last_exc is not None:
        raise AssertionError(f"condition not met within {timeout_s}s; last error={last_exc!r}")
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _retry_until_success(fn, timeout_s=120.0, interval_s=5.0):
    """Retry ``fn`` (an operation expected to eventually SUCCEED) tolerating transient
    ClientErrors (e.g. KMSInvalidStateException while a fresh replica settles) until it either
    succeeds or the timeout is hit, in which case the last exception is re-raised."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    if last_exc is not None:
        raise last_exc
    raise AssertionError(f"condition not met within {timeout_s}s")



def _best_effort_schedule_deletion(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
