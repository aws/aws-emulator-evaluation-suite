"""key-replication-regions-add-remove-state-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "key-replication-regions-add-remove-state-transition"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key created with a ReplicationRegion is a PRIMARY key whose ReplicationStatus for that region
    is IN_PROGRESS or SYNCHRONIZED and reaches SYNCHRONIZED, and RemoveKeyReplicationRegions removes the
    region's entry."""
    pc = ctx.client("payment-cryptography")
    target_region = _pick_target_region(ctx.region)

    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        ReplicationRegions=[target_region],
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    assert created["MultiRegionKeyType"] == "PRIMARY", (
        f"expected a fresh multi-region key to be PRIMARY, got {created['MultiRegionKeyType']!r}"
    )
    replication_status = created["ReplicationStatus"][target_region]["Status"]
    assert replication_status in ("IN_PROGRESS", "SYNCHRONIZED"), (
        f"expected {target_region} to start IN_PROGRESS or SYNCHRONIZED, got {replication_status!r}"
    )

    assert _poll_until(
        lambda: pc.get_key(KeyIdentifier=arn)["Key"]["ReplicationStatus"]
        .get(target_region, {})
        .get("Status")
        == "SYNCHRONIZED",
        timeout_s=120.0,
        interval_s=5.0,
    ), "replication to the target region never reached SYNCHRONIZED"

    pc.remove_key_replication_regions(KeyIdentifier=arn, ReplicationRegions=[target_region])

    assert _poll_until(
        lambda: target_region not in pc.get_key(KeyIdentifier=arn)["Key"].get(
            "ReplicationStatus", {}
        ),
        timeout_s=120.0,
        interval_s=5.0,
    ), "replication region was never removed from ReplicationStatus"


def _pick_target_region(current_region: str) -> str:
    # Multi-Region replication needs a genuine second region, not ctx.region itself; these
    # four are Payment Cryptography's own supported regions, so any one distinct from
    # ctx.region is a valid replication target.
    for candidate in ("us-west-2", "us-east-1", "eu-west-1", "ap-southeast-1"):
        if candidate != current_region:
            return candidate
    raise AssertionError("could not find a distinct candidate region for the test")


def _poll_until(predicate, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
