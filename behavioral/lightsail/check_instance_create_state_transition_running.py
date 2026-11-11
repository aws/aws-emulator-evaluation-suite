"""instance-create-state-transition-running."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "instance-create-state-transition-running"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstances provisions a VM that transitions from pending to running with a real public IP."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    name = ctx.unique_name("sim2real-ls-inst-")

    ls.create_instances(
        instanceNames=[name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=name, forceDeleteAddOns=True))

    # Instance starts in "pending" immediately after creation.
    first_state = ls.get_instance_state(instanceName=name)["state"]["name"]
    assert first_state in ("pending", "running"), f"unexpected initial state {first_state!r}"

    final_state = _wait_instance_state(ctx, name, "running", timeout_s=300.0)
    assert final_state == "running", f"expected running, got {final_state!r}"

    instance = ls.get_instance(instanceName=name)["instance"]
    actual_state = instance["state"]["name"]
    assert actual_state == "running", f"expected running on independent read, got {actual_state!r}"
    assert instance.get("publicIpAddress"), "running instance has no public IP address"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
