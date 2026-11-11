"""instance-reboot-preserves-public-ip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "instance-reboot-preserves-public-ip"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RebootInstance completes as a real async operation and preserves the dynamic public IP."""
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
    _wait_instance_state(ctx, name, "running", timeout_s=300.0)
    ip_before = ls.get_instance(instanceName=name)["instance"]["publicIpAddress"]

    reboot_op_id = ls.reboot_instance(instanceName=name)["operations"][0]["id"]

    final = _wait_instance_state(ctx, name, "running", timeout_s=180.0)
    assert final == "running", f"instance did not settle back to running after reboot, last={final!r}"

    # Independent read via GetOperationsForResource: proves RebootInstance actually ran as a
    # tracked async operation and did not fail server-side, not just that the state poll saw "running".
    op = _wait_operation_terminal(ctx, name, reboot_op_id, timeout_s=180.0)
    assert op["status"] in ("Succeeded", "Completed"), (
        f"RebootInstance operation {reboot_op_id} did not succeed: {op!r}"
    )

    ip_after = ls.get_instance(instanceName=name)["instance"]["publicIpAddress"]
    assert ip_after == ip_before, f"public IP changed across reboot: {ip_before!r} -> {ip_after!r}"


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


def _wait_operation_terminal(ctx, resource_name, op_id, timeout_s=180.0, interval_s=5.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        for op in ls.get_operations_for_resource(resourceName=resource_name)["operations"]:
            if op["id"] == op_id:
                last = op
                if op["isTerminal"]:
                    return op
                break
        time.sleep(interval_s)
    raise AssertionError(f"operation {op_id} on {resource_name} never reached terminal, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
