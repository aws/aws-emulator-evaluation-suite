"""default-replication-regions-enable-disable-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "default-replication-regions-enable-disable-roundtrip"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:payment-cryptography-default-key-replication")
def run(ctx) -> None:
    """EnableDefaultKeyReplicationRegions adds a region to the account's default Multi-Region
    replication configuration, and DisableDefaultKeyReplicationRegions removes it again."""
    pc = ctx.client("payment-cryptography")
    baseline = set(pc.get_default_key_replication_regions()["EnabledReplicationRegions"])
    target = _pick_region_not_in(ctx.region, baseline)

    pc.enable_default_key_replication_regions(ReplicationRegions=[target])
    ctx.on_cleanup(lambda: _safe_disable(pc, target))

    enabled = set(pc.get_default_key_replication_regions()["EnabledReplicationRegions"])
    assert target in enabled, f"expected {target} in EnabledReplicationRegions, got {enabled}"

    pc.disable_default_key_replication_regions(ReplicationRegions=[target])
    after = set(pc.get_default_key_replication_regions()["EnabledReplicationRegions"])
    assert target not in after, f"expected {target} removed from EnabledReplicationRegions, got {after}"


def _pick_region_not_in(current_region: str, baseline: set) -> str:
    # literals are candidate *target* regions for the account's Multi-Region default
    # replication list, not a pin on this check's own region or resources

    for candidate in ("us-west-2", "us-east-1", "eu-west-1", "ap-southeast-1"):
        if candidate != current_region and candidate not in baseline:
            return candidate
    raise AssertionError("could not find a free candidate region for the test")


def _safe_disable(pc, region: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.disable_default_key_replication_regions(ReplicationRegions=[region])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
