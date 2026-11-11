"""replicate-key-disabled-source-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "replicate-key-disabled-source-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]

# Not global or region-pinned: these are real ReplicateKey targets, and a multi-region
# replication test needs actual distinct AWS region literals to replicate into. All three are
# original (non-opt-in) partition regions, so they exist in every commercial account.
_CANDIDATE_REGIONS = ["us-west-2", "us-east-1", "eu-west-1"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A multi-Region primary replicates into one Region while Enabled; once disabled, ReplicateKey into a second
    Region fails with DisabledException "<arn> is disabled." and DescribeKey there fails with NotFoundException;
    after EnableKey the same call creates an Enabled replica in the second Region."""
    positive_region, negative_region = _two_other_regions(ctx)

    kms = ctx.client("kms")
    primary = kms.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-kms-replicate-disabled-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = primary["KeyId"]
    primary_arn = primary["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Positive control: while ENABLED, ReplicateKey genuinely creates a replica.
    positive_client = ctx.client("kms", region=positive_region)
    positive_replica_arn = kms.replicate_key(
        KeyId=key_id,
        ReplicaRegion=positive_region,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["ReplicaKeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: positive_client.schedule_key_deletion(
            KeyId=positive_replica_arn, PendingWindowInDays=7
        )
    )
    positive_state = _poll_until(
        lambda: positive_client.describe_key(KeyId=positive_replica_arn)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert positive_state["KeyState"] == "Enabled", positive_state["KeyState"]

    # Break exactly one thing: disable the primary, then try to replicate again
    # into a DIFFERENT (never-before-used) target region.
    kms.disable_key(KeyId=key_id)
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "Disabled", described["KeyState"]

    code, message = _error(lambda: kms.replicate_key(KeyId=key_id, ReplicaRegion=negative_region))
    assert code == "DisabledException", code
    assert message == f"{primary_arn} is disabled.", message

    # Effect absent: no replica was created in the negative-control region at all.
    partition, account = _partition_account(primary_arn)
    hypothetical_negative_arn = f"arn:{partition}:kms:{negative_region}:{account}:key/{key_id}"
    negative_client = ctx.client("kms", region=negative_region)
    code_describe, message_describe = _error(
        lambda: negative_client.describe_key(KeyId=hypothetical_negative_arn)
    )
    assert code_describe == "NotFoundException", code_describe
    assert message_describe == f"Key '{hypothetical_negative_arn}' does not exist", message_describe

    # Restore: re-enable the primary and prove the IDENTICAL call succeeds -- disablement,
    # not the region or the key itself, was the blocking condition.
    kms.enable_key(KeyId=key_id)
    restored = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert restored["KeyState"] == "Enabled", restored["KeyState"]

    negative_replica_arn = kms.replicate_key(
        KeyId=key_id,
        ReplicaRegion=negative_region,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["ReplicaKeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: negative_client.schedule_key_deletion(
            KeyId=negative_replica_arn, PendingWindowInDays=7
        )
    )
    negative_state = _poll_until(
        lambda: negative_client.describe_key(KeyId=negative_replica_arn)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert negative_state["KeyState"] == "Enabled", negative_state["KeyState"]


def _two_other_regions(ctx) -> tuple[str, str]:
    candidates = [r for r in _CANDIDATE_REGIONS if r != ctx.region]
    return candidates[0], candidates[1]


def _partition_account(arn: str) -> tuple[str, str]:
    parts = arn.split(":")
    return parts[1], parts[4]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
