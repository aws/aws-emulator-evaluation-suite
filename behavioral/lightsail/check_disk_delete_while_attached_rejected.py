"""disk-delete-while-attached-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disk-delete-while-attached-rejected"
GROUP = "overly-permissive"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDisk on a disk currently attached to an instance is rejected; the disk survives until detached."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    instance_name = ctx.unique_name("sim2real-ls-inst-")
    disk_name = ctx.unique_name("sim2real-ls-disk-")
    control_disk_name = ctx.unique_name("sim2real-ls-diskctl-")

    ls.create_instances(
        instanceNames=[instance_name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
        tags=[{"key": "sim2real", "value": "disk-delete-while-attached-rejected"}],
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_name, "running", timeout_s=300.0)

    ls.create_disk(
        diskName=disk_name,
        availabilityZone=zone,
        sizeInGb=8,
        tags=[{"key": "sim2real", "value": "disk-delete-while-attached-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_disk(ctx, disk_name))
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)
    ls.attach_disk(diskName=disk_name, instanceName=instance_name, diskPath="/dev/xvdf")
    _wait_disk_state(ctx, disk_name, "in-use", timeout_s=120.0)

    code, message = _error(lambda: ls.delete_disk(diskName=disk_name))
    assert code == "OperationFailureException", f"unexpected code deleting attached disk: {code!r}"
    assert message == (
        "You can't perform this operation because the disk is still attached to a Lightsail "
        f"instance: {instance_name}."
    ), f"unexpected message deleting attached disk: {message!r}"

    still_there = ls.get_disk(diskName=disk_name)["disk"]
    assert still_there["state"] == "in-use"
    assert still_there["isAttached"] is True

    # DetachDisk requires the target instance to be stopped first.
    ls.stop_instance(instanceName=instance_name)
    _wait_instance_state(ctx, instance_name, "stopped", timeout_s=180.0)

    ls.detach_disk(diskName=disk_name)
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)
    ls.delete_disk(diskName=disk_name)
    _assert_disk_gone(ctx, disk_name)

    second_delete_code, second_delete_message = _error(lambda: ls.delete_disk(diskName=disk_name))
    assert second_delete_code == "NotFoundException", (
        f"deleting an already-deleted disk should fail not-found, got {second_delete_code!r}"
    )
    assert second_delete_message == f"The Disk does not exist: {disk_name}", (
        f"unexpected message re-deleting disk: {second_delete_message!r}"
    )

    # Positive control: deleting an unattached disk succeeds outright.
    ls.create_disk(
        diskName=control_disk_name,
        availabilityZone=zone,
        sizeInGb=8,
        tags=[{"key": "sim2real", "value": "disk-delete-while-attached-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_disk(ctx, control_disk_name))
    _wait_disk_state(ctx, control_disk_name, "available", timeout_s=120.0)
    ls.delete_disk(diskName=control_disk_name)
    _assert_disk_gone(ctx, control_disk_name)

    second_control_delete_code, second_control_delete_message = _error(
        lambda: ls.delete_disk(diskName=control_disk_name)
    )
    assert second_control_delete_code == "NotFoundException", (
        f"deleting an already-deleted disk should fail not-found, got {second_control_delete_code!r}"
    )
    assert second_control_delete_message == f"The Disk does not exist: {control_disk_name}", (
        f"unexpected message re-deleting control disk: {second_control_delete_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _assert_disk_gone(ctx, disk_name, timeout_s=60.0, interval_s=2.0):
    ls = ctx.client("lightsail")
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ls.get_disk(diskName=disk_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"disk {disk_name} was not removed within {timeout_s}s")


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
