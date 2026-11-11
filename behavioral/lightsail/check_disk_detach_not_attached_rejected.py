"""disk-detach-not-attached-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disk-detach-not-attached-rejected"
GROUP = "overly-permissive"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetachDisk on a disk that is not currently attached to anything is rejected and the disk stays available."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    disk_name = ctx.unique_name("sim2real-ls-disk-")
    instance_name = ctx.unique_name("sim2real-ls-inst-")
    control_disk_name = ctx.unique_name("sim2real-ls-diskctl-")

    ls.create_disk(diskName=disk_name, availabilityZone=zone, sizeInGb=8)
    ctx.on_cleanup(lambda: ls.delete_disk(diskName=disk_name, forceDeleteAddOns=True))
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)

    code, message = _error(lambda: ls.detach_disk(diskName=disk_name))
    assert code == "OperationFailureException", f"unexpected code detaching unattached disk: {code!r}"
    assert message == "You can't detach this disk right now. The state of this disk is: available.", (
        f"unexpected message detaching unattached disk: {message!r}"
    )

    disk = ls.get_disk(diskName=disk_name)["disk"]
    assert disk["state"] == "available", f"expected disk state 'available', got {disk['state']!r}"
    assert disk["isAttached"] is False, f"expected isAttached False, got {disk['isAttached']!r}"

    # Positive control: detaching a disk that IS attached succeeds.
    ls.create_instances(
        instanceNames=[instance_name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_name, "running", timeout_s=300.0)

    ls.create_disk(diskName=control_disk_name, availabilityZone=zone, sizeInGb=8)
    ctx.on_cleanup(lambda: ls.delete_disk(diskName=control_disk_name, forceDeleteAddOns=True))
    _wait_disk_state(ctx, control_disk_name, "available", timeout_s=120.0)
    ls.attach_disk(diskName=control_disk_name, instanceName=instance_name, diskPath="/dev/xvdf")
    _wait_disk_state(ctx, control_disk_name, "in-use", timeout_s=120.0)
    ls.stop_instance(instanceName=instance_name)
    _wait_instance_state(ctx, instance_name, "stopped", timeout_s=180.0)
    ls.detach_disk(diskName=control_disk_name)
    control_final = _wait_disk_state(ctx, control_disk_name, "available", timeout_s=120.0)
    assert control_final == "available", f"expected control disk 'available' after detach, got {control_final!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
