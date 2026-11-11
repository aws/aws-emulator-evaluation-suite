"""static-ip-attach-detach-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "static-ip-attach-detach-lifecycle"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachStaticIp reassigns the instance's public IP to the static IP; DetachStaticIp reverses it."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    instance_name = ctx.unique_name("sim2real-ls-inst-")
    static_ip_name = ctx.unique_name("sim2real-ls-sip-")

    ls.create_instances(
        instanceNames=[instance_name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_name, "running", timeout_s=300.0)

    ls.allocate_static_ip(staticIpName=static_ip_name)
    ctx.on_cleanup(lambda: ls.release_static_ip(staticIpName=static_ip_name))
    static_ip = ls.get_static_ip(staticIpName=static_ip_name)["staticIp"]
    assert static_ip["isAttached"] is False, (
        f"expected a freshly allocated static IP to be unattached, got isAttached={static_ip['isAttached']!r}"
    )

    ls.attach_static_ip(staticIpName=static_ip_name, instanceName=instance_name)
    attached = _wait_static_ip_attached(ctx, static_ip_name, True, timeout_s=60.0)
    assert attached["isAttached"] is True, (
        f"expected isAttached=True after AttachStaticIp, got {attached['isAttached']!r}"
    )
    assert attached["attachedTo"] == instance_name, (
        f"expected attachedTo={instance_name!r}, got {attached['attachedTo']!r}"
    )

    instance = ls.get_instance(instanceName=instance_name)["instance"]
    assert instance["publicIpAddress"] == attached["ipAddress"], (
        f"expected instance publicIpAddress {instance['publicIpAddress']!r} to equal the "
        f"attached static IP address {attached['ipAddress']!r}"
    )

    ls.detach_static_ip(staticIpName=static_ip_name)
    detached = _wait_static_ip_attached(ctx, static_ip_name, False, timeout_s=60.0)
    assert detached["isAttached"] is False, (
        f"expected isAttached=False after DetachStaticIp, got {detached['isAttached']!r}"
    )

    instance_after_detach = ls.get_instance(instanceName=instance_name)["instance"]
    assert instance_after_detach["publicIpAddress"] != attached["ipAddress"], (
        f"expected the instance to lose the static IP {attached['ipAddress']!r} after DetachStaticIp, "
        f"but publicIpAddress is still {instance_after_detach['publicIpAddress']!r}"
    )


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
    with_ipv4 = [b for b in active if b.get("publicIpv4AddressCount", 1) > 0]
    pool = with_ipv4 or active
    pool.sort(key=lambda b: b["price"])
    return pool[0]["bundleId"]


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


def _wait_static_ip_attached(ctx, static_ip_name, target, timeout_s=60.0, interval_s=2.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ls.get_static_ip(staticIpName=static_ip_name)["staticIp"]
        if last["isAttached"] == target:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"static ip {static_ip_name} isAttached never became {target!r}, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
