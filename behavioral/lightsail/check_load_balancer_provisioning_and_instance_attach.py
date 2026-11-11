"""load-balancer-provisioning-and-instance-attach."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "load-balancer-provisioning-and-instance-attach"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new load balancer reaches active state, attaching an instance surfaces it in the health
    summary, and detaching it drains it out of service."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    instance_name = ctx.unique_name("sim2real-ls-inst-")
    lb_name = ctx.unique_name("sim2real-ls-lb-")

    ls.create_instances(
        instanceNames=[instance_name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))

    # Kick off the load balancer immediately, before waiting on the instance: the two
    # provisioning processes run concurrently on AWS's side, so waiting on one before even
    # starting the other needlessly serializes two independent async operations.
    ls.create_load_balancer(loadBalancerName=lb_name, instancePort=80)
    ctx.on_cleanup(lambda: ls.delete_load_balancer(loadBalancerName=lb_name))

    _wait_instance_state(ctx, instance_name, "running", timeout_s=120.0)
    lb_state = _wait_lb_state(ctx, lb_name, {"active", "active_impaired"}, timeout_s=600.0)
    assert lb_state in ("active", "active_impaired"), f"load balancer never became active, last={lb_state!r}"

    ls.attach_instances_to_load_balancer(loadBalancerName=lb_name, instanceNames=[instance_name])
    summary = _wait_lb_health_summary(ctx, lb_name, instance_name, timeout_s=60.0)
    assert summary is not None, "attached instance never appeared in load balancer health summary"
    # Positive control for the drain check below: a freshly-attached instance must not already
    # read "draining", or a target that fakes draining unconditionally would pass it for free.
    assert summary.get("instanceHealth") != "draining", (
        f"newly attached instance already reports draining: {summary.get('instanceHealth')!r}"
    )

    ls.detach_instances_from_load_balancer(loadBalancerName=lb_name, instanceNames=[instance_name])
    # Real Lightsail holds a detached instance in "draining" for its connection-draining delay
    # (observed past 160s) before it leaves the health summary. "draining" is transient, so the
    # graded outcome is the terminal one: the instance is gone from the summary.
    _wait_lb_health_drained(ctx, lb_name, instance_name, timeout_s=600.0)


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


def _wait_lb_state(ctx, lb_name, targets, timeout_s=300.0, interval_s=5.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ls.get_load_balancer(loadBalancerName=lb_name)["loadBalancer"]["state"]
        if last in targets:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"load balancer {lb_name} state never reached {targets}, last={last!r}")


def _wait_lb_health_summary(ctx, lb_name, instance_name, timeout_s=120.0, interval_s=3.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summaries = ls.get_load_balancer(loadBalancerName=lb_name)["loadBalancer"]["instanceHealthSummary"]
        for s in summaries:
            if s["instanceName"] == instance_name:
                return s
        time.sleep(interval_s)
    return None


def _wait_lb_health_drained(ctx, lb_name, instance_name, timeout_s=600.0, interval_s=10.0):
    """Poll until the detached instance is absent from the health summary; raise on timeout."""
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        # The key itself is omitted once no instance is attached.
        summaries = ls.get_load_balancer(loadBalancerName=lb_name)["loadBalancer"].get("instanceHealthSummary", [])
        match = next((s for s in summaries if s["instanceName"] == instance_name), None)
        if match is None:
            return
        last = match.get("instanceHealth")
        time.sleep(interval_s)
    raise AssertionError(
        f"detached instance {instance_name} still in the health summary after {timeout_s}s, "
        f"last instanceHealth={last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
