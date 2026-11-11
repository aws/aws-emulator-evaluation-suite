"""disk-attach-already-attached-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disk-attach-already-attached-rejected"
GROUP = "overly-permissive"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachDisk on a disk already attached to another instance is rejected, the original attachment
    is unchanged, and restoring the disk (detach) lets the identical call succeed against instance_b."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    instance_a = ctx.unique_name("sim2real-ls-insta-")
    instance_b = ctx.unique_name("sim2real-ls-instb-")
    disk_name = ctx.unique_name("sim2real-ls-disk-")

    ls.create_instances(
        instanceNames=[instance_a, instance_b],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_b, forceDeleteAddOns=True))
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_a, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_a, "running", timeout_s=300.0)
    _wait_instance_state(ctx, instance_b, "running", timeout_s=300.0)

    ls.create_disk(
        diskName=disk_name,
        availabilityZone=zone,
        sizeInGb=8,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_disk(ctx, disk_name))
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)

    # Positive control: attaching to instance_a succeeds outright.
    ls.attach_disk(diskName=disk_name, instanceName=instance_a, diskPath="/dev/xvdf")
    _wait_disk_state(ctx, disk_name, "in-use", timeout_s=120.0)

    code, message = _error(lambda: ls.attach_disk(diskName=disk_name, instanceName=instance_b, diskPath="/dev/xvdg"))
    assert code == "OperationFailureException", f"unexpected code re-attaching in-use disk: {code!r}"
    assert message == "You can't attach this disk right now. The state of this disk is: in-use.", (
        f"unexpected message re-attaching in-use disk: {message!r}"
    )

    disk = ls.get_disk(diskName=disk_name)["disk"]
    assert disk["attachedTo"] == instance_a, (
        f"disk attachment moved after rejected re-attach: attachedTo={disk['attachedTo']!r}"
    )
    assert disk["isAttached"] is True, f"disk reports isAttached={disk['isAttached']!r} after rejected re-attach"

    # Restore: detach from instance_a (DetachDisk requires the instance stopped first), then retry
    # the identical call that was just rejected — it must now succeed against instance_b.
    ls.stop_instance(instanceName=instance_a)
    _wait_instance_state(ctx, instance_a, "stopped", timeout_s=180.0)
    ls.detach_disk(diskName=disk_name)
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)

    ls.attach_disk(diskName=disk_name, instanceName=instance_b, diskPath="/dev/xvdg")
    after = _wait_disk_state(ctx, disk_name, "in-use", timeout_s=120.0)
    assert after == "in-use", f"identical attach call after restore never reached in-use, last={after!r}"
    disk_after_retry = ls.get_disk(diskName=disk_name)["disk"]
    assert disk_after_retry["attachedTo"] == instance_b, (
        f"identical attach call after restore did not move attachment to instance_b: "
        f"attachedTo={disk_after_retry['attachedTo']!r}"
    )

    # Detach again in-body (stopping instance_b) so cleanup deletes an already-unattached disk —
    # DeleteDisk fails on a disk still attached to a running instance.
    ls.stop_instance(instanceName=instance_b)
    _wait_instance_state(ctx, instance_b, "stopped", timeout_s=180.0)
    ls.detach_disk(diskName=disk_name)
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target accepting
    what real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


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
