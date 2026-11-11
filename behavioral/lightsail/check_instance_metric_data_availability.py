"""instance-metric-data-availability."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "instance-metric-data-availability"
GROUP = "telemetry"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A running instance's CPUUtilization metric eventually becomes available through GetInstanceMetricData."""
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
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_name, "running", timeout_s=300.0)

    deadline = time.monotonic() + 480.0
    datapoints = []
    while time.monotonic() < deadline:
        now = datetime.datetime.now(datetime.timezone.utc)
        resp = ls.get_instance_metric_data(
            instanceName=instance_name,
            metricName="CPUUtilization",
            period=300,
            startTime=now - datetime.timedelta(minutes=20),
            endTime=now,
            unit="Percent",
            statistics=["Average"],
        )
        datapoints = resp.get("metricData", [])
        if datapoints:
            break
        time.sleep(2)

    if not datapoints:
        raise AssertionError(
            "CPUUtilization metric data had not landed for the instance within the poll window; "
            "CloudWatch-backed Lightsail metrics can take several minutes to appear on real AWS"
        )

    assert any("average" in dp for dp in datapoints), f"no average datapoint present: {datapoints!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
