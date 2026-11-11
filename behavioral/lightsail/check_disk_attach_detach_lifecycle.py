"""disk-attach-detach-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disk-attach-detach-lifecycle"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachDisk/DetachDisk drive a disk through available->in-use->available and update instance linkage."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    instance_name = ctx.unique_name("sim2real-ls-inst-")
    disk_name = ctx.unique_name("sim2real-ls-disk-")

    ls.create_instances(
        instanceNames=[instance_name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_name, "running", timeout_s=300.0)

    ls.create_disk(diskName=disk_name, availabilityZone=zone, sizeInGb=8)
    ctx.on_cleanup(lambda: _safe_delete_disk(ctx, disk_name))
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)

    ls.attach_disk(diskName=disk_name, instanceName=instance_name, diskPath="/dev/xvdf")
    _wait_disk_state(ctx, disk_name, "in-use", timeout_s=120.0)
    disk = ls.get_disk(diskName=disk_name)["disk"]
    assert disk["isAttached"] is True, f"expected isAttached=True after AttachDisk, got {disk['isAttached']!r}"
    assert disk["attachedTo"] == instance_name, (
        f"expected attachedTo={instance_name!r}, got {disk['attachedTo']!r}"
    )

    # DetachDisk requires the target instance to be stopped first.
    ls.stop_instance(instanceName=instance_name)
    _wait_instance_state(ctx, instance_name, "stopped", timeout_s=180.0)

    ls.detach_disk(diskName=disk_name)
    after = _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)
    assert after == "available", f"expected disk state=available after DetachDisk, got {after!r}"
    disk = ls.get_disk(diskName=disk_name)["disk"]
    assert disk["isAttached"] is False, f"expected isAttached=False after DetachDisk, got {disk['isAttached']!r}"


def _pick_zone(ctx):
    ls = ctx.client("lightsail")
    resp = ls.get_regions(includeAvailabilityZones=True)
    for r in resp["regions"]:
        if r["name"] == ctx.region:
            zones = r.get("availabilityZones") or []
            if zones:
                return zones[0]["zoneName"]
    raise AssertionError(f"no availability zone found for region {ctx.region}")


def _pick_blueprint(ctx):
    ls = ctx.client("lightsail")
    resp = ls.get_blueprints()
    active = [b for b in resp["blueprints"] if b.get("isActive")]
    for b in active:
        if "amazon_linux" in b["blueprintId"]:
            return b["blueprintId"]
    return active[0]["blueprintId"]


def _pick_bundle(ctx):
    ls = ctx.client("lightsail")
    resp = ls.get_bundles()
    active = [b for b in resp["bundles"] if b.get("isActive")]
    active.sort(key=lambda b: b["price"])
    return active[0]["bundleId"]


def _wait_instance_state(ctx, name, target, timeout_s=300.0, interval_s=5.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ls.get_instance_state(instanceName=name)["state"]["name"]
        if last == target:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"instance {name} state never reached {target!r}, last={last!r}")


def _wait_disk_state(ctx, disk_name, target, timeout_s=120.0, interval_s=3.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ls.get_disk(diskName=disk_name)["disk"]["state"]
        if last == target:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"disk {disk_name} state never reached {target!r}, last={last!r}")


def _safe_delete_disk(ctx, disk_name):
    """Cleanup helper that detaches (if needed) before deleting, tolerating a disk already gone."""
    ls = ctx.client("lightsail")
    from botocore.exceptions import ClientError

    try:
        disk = ls.get_disk(diskName=disk_name)["disk"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    if disk.get("isAttached"):
        try:
            ls.detach_disk(diskName=disk_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            if not ls.get_disk(diskName=disk_name)["disk"].get("isAttached"):
                break
            time.sleep(3.0)
    try:
        ls.delete_disk(diskName=disk_name, forceDeleteAddOns=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
