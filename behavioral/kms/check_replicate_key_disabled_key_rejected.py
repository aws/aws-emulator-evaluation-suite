"""replicate-key-disabled-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicate-key-disabled-key-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]

# ReplicateKey needs a literal target region distinct from the primary's; there is no API to
# discover "some other region that supports KMS multi-Region keys", so a candidate list is the
# only way to pick one -- not a region-pinned resource.
_CANDIDATE_REGIONS = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-southeast-1"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReplicateKey on a disabled multi-Region primary fails with DisabledException "<arn> is disabled.", the
    primary lists no replicas and DescribeKey in the target Region fails with NotFoundException and the exact
    message; after EnableKey the same call creates an Enabled REPLICA in that Region."""
    primary_region = ctx.region
    (replica_region,) = _pick_regions(primary_region, 1)
    kms = ctx.client("kms")
    replica_kms = ctx.client("kms", region=replica_region)

    created = kms.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-mrk-disabled-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    key_arn = created["KeyMetadata"]["Arn"]
    partition, account = key_arn.split(":")[1], key_arn.split(":")[4]
    replica_arn_expected = f"arn:{partition}:kms:{replica_region}:{account}:key/{key_id}"
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    kms.disable_key(KeyId=key_id)
    disabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Disabled",
        timeout_s=60,
        interval_s=2,
    )
    assert disabled["KeyState"] == "Disabled", disabled["KeyState"]

    code, message = _error(lambda: kms.replicate_key(KeyId=key_id, ReplicaRegion=replica_region))
    assert code == "DisabledException", f"expected DisabledException, got {code}"
    assert message == f"{key_arn} is disabled.", message

    # effect-absent, side one: the disabled primary's own replica set is still empty -- no
    # partial replica in its bookkeeping.
    still_none = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    replica_keys = still_none["MultiRegionConfiguration"]["ReplicaKeys"]
    assert replica_keys == [], f"expected no replicas on the primary, found {replica_keys}"

    # effect-absent, side two: an INDEPENDENT read issued at the destination region itself (not
    # the primary's bookkeeping) also sees nothing -- a target that fakes the primary's replica
    # list without ever provisioning the replica would still fail here.
    destination_code, destination_message = _error(lambda: replica_kms.describe_key(KeyId=key_id))
    assert destination_code == "NotFoundException", (
        f"expected no key at the destination region, got {destination_code}"
    )
    assert destination_message == f"Key '{replica_arn_expected}' does not exist", destination_message

    # positive control: re-enable the primary, then the identical ReplicateKey call succeeds
    kms.enable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    replica_arn = kms.replicate_key(
        KeyId=key_id,
        ReplicaRegion=replica_region,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )["ReplicaKeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(replica_kms, replica_arn))

    # terminal read, independent and AT the destination: the replica itself must actually reach
    # Enabled there, not merely be named in the primary's ReplicaKeys list.
    replica_state = _poll_until(
        lambda: replica_kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=120,
        interval_s=5,
    )
    assert replica_state["KeyState"] == "Enabled", replica_state["KeyState"]
    assert replica_state["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        replica_state["MultiRegionConfiguration"]
    )

    replicated = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    replicated_regions = {r["Region"] for r in replicated["MultiRegionConfiguration"]["ReplicaKeys"]}
    assert replicated_regions == {replica_region}, replicated_regions


def _pick_regions(exclude_region, n):
    picked = [r for r in _CANDIDATE_REGIONS if r != exclude_region][:n]
    if len(picked) < n:
        raise AssertionError("not enough candidate regions distinct from ctx.region")
    return picked


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
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
