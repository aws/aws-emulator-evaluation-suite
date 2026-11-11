"""alarm-configuration-roundtrip-and-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-configuration-roundtrip-and-delete"
GROUP = "telemetry"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarm persists the exact alarm configuration; DeleteAlarm removes it from GetAlarms entirely."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    blueprint_id = _pick_blueprint(ctx)
    bundle_id = _pick_bundle(ctx)
    instance_name = ctx.unique_name("sim2real-ls-inst-")
    alarm_name = ctx.unique_name("sim2real-ls-alarm-")

    ls.create_instances(
        instanceNames=[instance_name],
        availabilityZone=zone,
        blueprintId=blueprint_id,
        bundleId=bundle_id,
    )
    ctx.on_cleanup(lambda: ls.delete_instance(instanceName=instance_name, forceDeleteAddOns=True))
    _wait_instance_state(ctx, instance_name, "running", timeout_s=300.0)

    ls.put_alarm(
        alarmName=alarm_name,
        metricName="CPUUtilization",
        monitoredResourceName=instance_name,
        comparisonOperator="GreaterThanThreshold",
        threshold=90.0,
        evaluationPeriods=1,
        notificationEnabled=False,
    )
    alarm_deleted = False

    def _cleanup_alarm():
        if not alarm_deleted:
            ls.delete_alarm(alarmName=alarm_name)

    ctx.on_cleanup(_cleanup_alarm)

    alarms = ls.get_alarms(monitoredResourceName=instance_name)["alarms"]
    match = next((a for a in alarms if a["name"] == alarm_name), None)
    assert match is not None, "PutAlarm's alarm not found via GetAlarms"
    assert match["metricName"] == "CPUUtilization", f"expected metricName CPUUtilization, got {match['metricName']}"
    assert match["comparisonOperator"] == "GreaterThanThreshold", (
        f"expected comparisonOperator GreaterThanThreshold, got {match['comparisonOperator']}"
    )
    assert match["threshold"] == 90.0, f"expected threshold 90.0, got {match['threshold']}"
    assert match["evaluationPeriods"] == 1, f"expected evaluationPeriods 1, got {match['evaluationPeriods']}"
    assert match["monitoredResourceInfo"]["name"] == instance_name, (
        f"expected monitoredResourceInfo.name {instance_name}, got {match['monitoredResourceInfo']['name']}"
    )

    ls.delete_alarm(alarmName=alarm_name)
    alarm_deleted = True
    remaining = ls.get_alarms(monitoredResourceName=instance_name)["alarms"]
    assert not any(a["name"] == alarm_name for a in remaining), "deleted alarm still present in GetAlarms"

    try:
        ls.delete_alarm(alarmName=alarm_name)
        raise AssertionError("DeleteAlarm on an already-deleted alarm unexpectedly succeeded")
    except ls.exceptions.NotFoundException as exc:
        expected = (
            f"The specified resource {alarm_name} does not exist within types [Alarm]. "
            "Please provide a valid resource name."
        )
        assert exc.response["Error"]["Message"] == expected, (
            f"expected the not-found message {expected!r}, got {exc}"
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
