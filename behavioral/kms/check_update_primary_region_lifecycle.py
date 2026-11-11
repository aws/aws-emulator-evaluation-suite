"""update-primary-region-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-primary-region-lifecycle"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion promotes a replica to primary and demotes the former primary to a
    replica; DescribeKey in BOTH Regions converges on the new MultiRegionConfiguration roles."""
    region_a = ctx.region
    region_b = _alt_region(region_a)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    primary = kms_a.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-upr-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = primary["KeyMetadata"]["KeyId"]
    arn_a = primary["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_a, key_id))
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_b, key_id))

    replicated = kms_a.replicate_key(KeyId=key_id, ReplicaRegion=region_b)
    arn_b = replicated["ReplicaKeyMetadata"]["Arn"]

    def _replica_enabled() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    assert (
        _poll_until(_replica_enabled, timeout_s=300.0, interval_s=5.0) is not None
    ), f"replica of {key_id} in {region_b} never reached KeyState=Enabled within 300s"

    # UpdatePrimaryRegion is called FROM the current primary's Region, naming the Region of the
    # replica that should become the new primary.
    kms_a.update_primary_region(KeyId=key_id, PrimaryRegion=region_b)

    def _roles_swapped() -> tuple[dict[str, Any], dict[str, Any]] | None:
        desc_a = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]
        desc_b = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        mrc_a = desc_a.get("MultiRegionConfiguration", {})
        mrc_b = desc_b.get("MultiRegionConfiguration", {})
        if mrc_a.get("MultiRegionKeyType") == "REPLICA" and mrc_b.get(
            "MultiRegionKeyType"
        ) == "PRIMARY":
            return desc_a, desc_b
        return None

    swapped = _poll_until(_roles_swapped, timeout_s=180.0, interval_s=5.0)
    assert swapped is not None, "primary/replica roles never converged after UpdatePrimaryRegion"
    desc_a, desc_b = swapped

    mrc_a = desc_a["MultiRegionConfiguration"]
    mrc_b = desc_b["MultiRegionConfiguration"]
    assert mrc_a["MultiRegionKeyType"] == "REPLICA", (
        f"expected {region_a}'s former-primary key to demote to REPLICA, got {mrc_a}"
    )
    assert mrc_a["PrimaryKey"]["Arn"] == arn_b, mrc_a["PrimaryKey"]
    assert mrc_b["MultiRegionKeyType"] == "PRIMARY", (
        f"expected {region_b}'s promoted replica to report PRIMARY, got {mrc_b}"
    )
    replica_arns_of_b = {rk["Arn"] for rk in mrc_b["ReplicaKeys"]}
    assert arn_a in replica_arns_of_b, mrc_b["ReplicaKeys"]


def _alt_region(region: str) -> str:
    # A multi-region key needs a second, genuinely distinct AWS Region to replicate into; the
    # pair chosen carries no other significance and is not a service-side constraint -- us-east-1
    # and us-west-2 are used because both are enabled by default in every commercial account.
    return "us-west-2" if region != "us-west-2" else "us-east-1"


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(
    probe: Callable[[], Any], *, timeout_s: float, interval_s: float = 1.0
) -> Any | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
