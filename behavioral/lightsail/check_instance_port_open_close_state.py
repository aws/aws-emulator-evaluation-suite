"""instance-port-open-close-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "instance-port-open-close-state"
GROUP = "data-plane"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OpenInstancePublicPorts/CloseInstancePublicPorts mutate the instance firewall observed by GetInstancePortStates."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    instance_name = ctx.unique_name("sim2real-ls-inst-")

    ls.create_instances(
        instanceNames=[instance_name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_name, "running", timeout_s=300.0)

    port_info = {"fromPort": 8443, "toPort": 8443, "protocol": "tcp", "cidrs": ["203.0.113.0/24"]}
    ls.open_instance_public_ports(portInfo=port_info, instanceName=instance_name)

    opened = _wait_port_present(ctx, instance_name, 8443, timeout_s=60.0)
    assert opened is not None, "opened port 8443 not found in GetInstancePortStates"
    assert opened["state"] == "open", f"expected state 'open', got {opened['state']!r}"
    assert opened["protocol"] == "tcp", f"expected protocol 'tcp', got {opened['protocol']!r}"

    ls.close_instance_public_ports(portInfo=port_info, instanceName=instance_name)
    closed = _wait_port_absent(ctx, instance_name, 8443, timeout_s=60.0)
    assert closed, "port 8443 still present in GetInstancePortStates after CloseInstancePublicPorts"


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


def _wait_port_present(ctx, instance_name, port, timeout_s=60.0, interval_s=2.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = ls.get_instance_port_states(instanceName=instance_name)["portStates"]
        for p in states:
            if p["fromPort"] == port and p["toPort"] == port:
                return p
        time.sleep(interval_s)
    return None


def _wait_port_absent(ctx, instance_name, port, timeout_s=60.0, interval_s=2.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = ls.get_instance_port_states(instanceName=instance_name)["portStates"]
        if not any(p["fromPort"] == port and p["toPort"] == port for p in states):
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
