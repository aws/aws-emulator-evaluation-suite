"""replicate-key-already-exists-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicate-key-already-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]

_CANDIDATE_REGIONS = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-southeast-1"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReplicateKey to a Region that already holds a replica fails with AlreadyExistsException and
    adds no duplicate entry; replicating to a new Region still succeeds."""
    primary_region = ctx.region
    region_b, region_c = _pick_regions(primary_region, 2)
    kms = ctx.client("kms")

    created = kms.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-mrk-dup-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    kms.replicate_key(KeyId=key_id, ReplicaRegion=region_b)
    after_first = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: any(r["Region"] == region_b for r in m["MultiRegionConfiguration"]["ReplicaKeys"]),
        timeout_s=120,
        interval_s=5,
    )
    count_b_before = sum(
        1 for r in after_first["MultiRegionConfiguration"]["ReplicaKeys"] if r["Region"] == region_b
    )
    assert count_b_before == 1, (
        f"expected exactly 1 replica entry for {region_b} after the first ReplicateKey, "
        f"got {count_b_before}: {after_first['MultiRegionConfiguration']['ReplicaKeys']!r}"
    )

    # A duplicate ReplicateKey while the replica is still Creating can return 200, so wait for
    # the replica to be Enabled first.
    kms_b = ctx.client("kms", region=region_b)
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms_b, key_id))
    _poll_until(
        lambda: kms_b.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=300,
        interval_s=5,
    )
    code, message = _error(lambda: kms.replicate_key(KeyId=key_id, ReplicaRegion=region_b))
    assert code == "AlreadyExistsException", f"unexpected error code: {code!r}"
    assert message == "You can create only one replica of each primary key in each AWS Region.", (
        message
    )

    after_reject = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    count_b_after = sum(
        1 for r in after_reject["MultiRegionConfiguration"]["ReplicaKeys"] if r["Region"] == region_b
    )
    assert count_b_after == 1, (
        f"the rejected duplicate ReplicateKey must not create a second entry for {region_b}, "
        f"got {count_b_after}: {after_reject['MultiRegionConfiguration']['ReplicaKeys']!r}"
    )

    kms.replicate_key(KeyId=key_id, ReplicaRegion=region_c)
    kms_c = ctx.client("kms", region=region_c)
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms_c, key_id))
    after_second = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: any(r["Region"] == region_c for r in m["MultiRegionConfiguration"]["ReplicaKeys"]),
        timeout_s=120,
        interval_s=5,
    )
    got_regions = {r["Region"] for r in after_second["MultiRegionConfiguration"]["ReplicaKeys"]}
    assert got_regions == {region_b, region_c}, (
        f"expected replica set {{region_b, region_c}} = {{{region_b!r}, {region_c!r}}} after "
        f"replicating to a genuinely new region, got {got_regions!r}"
    )


def _pick_regions(exclude_region, n):
    picked = [r for r in _CANDIDATE_REGIONS if r != exclude_region][:n]
    if len(picked) < n:
        raise AssertionError("not enough candidate regions distinct from ctx.region")
    return picked


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


def _best_effort_schedule_deletion(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


