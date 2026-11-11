"""modify-hosts-auto-placement-state-transition."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-hosts-auto-placement-state-transition"
GROUP = "state-machine"
SERVICES = ["ec2"]


# Dedicated Host quotas are granted per instance-family group and independently adjustable;
# a fresh/sandbox account can genuinely have a 0 quota for one family (e.g. m5) while another
# family has quota available. Try a small set of common families across every available AZ
# instead of hardcoding one family that may have no quota in this account/region.
_CANDIDATE_HOST_TYPES = ("m5.large", "c5.large", "r5.large", "m6i.large", "c6i.large")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyHosts toggling AutoPlacement is durably reflected on subsequent
    DescribeHosts calls for the dedicated host."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-host-")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]

    host_id, _instance_type, _az = _allocate_host_with_fallback(
        ec2, azs, _tag_spec("dedicated-host", name)
    )
    ctx.on_cleanup(lambda: ec2.release_hosts(HostIds=[host_id]))

    def _host():
        return ec2.describe_hosts(HostIds=[host_id])["Hosts"][0]

    started = _poll_until(
        _host, lambda h: h["State"] in ("available", "under-assessment"), timeout_s=60, interval_s=3
    )
    assert started["AutoPlacement"] == "off", (
        f"expected AutoPlacement='off' right after allocation, got {started['AutoPlacement']!r}"
    )

    ec2.modify_hosts(HostIds=[host_id], AutoPlacement="on")

    updated = _poll_until(
        _host, lambda h: h["AutoPlacement"] == "on", timeout_s=60, interval_s=3
    )
    assert updated["AutoPlacement"] == "on", (
        f"expected AutoPlacement='on' after ModifyHosts(AutoPlacement='on'), got {updated['AutoPlacement']!r}"
    )

    # Toggle back off and confirm the reverse transition is equally durable.
    ec2.modify_hosts(HostIds=[host_id], AutoPlacement="off")
    reverted = _poll_until(
        _host, lambda h: h["AutoPlacement"] == "off", timeout_s=60, interval_s=3
    )
    assert reverted["AutoPlacement"] == "off", (
        f"expected AutoPlacement='off' after ModifyHosts(AutoPlacement='off'), got {reverted['AutoPlacement']!r}"
    )


def _allocate_host_with_fallback(
    ec2,
    azs: list[str],
    tag_spec: list[dict[str, Any]],
    *,
    instance_types: tuple[str, ...] = _CANDIDATE_HOST_TYPES,
    passes: int = 2,
    retry_interval_s: float = 5.0,
):
    """Allocate one Dedicated Host, trying every (AZ, instance family) combination before
    giving up. HostLimitExceeded means this account/region has 0 quota for that specific
    family, which a fresh sandbox account can genuinely have for some families and not
    others; InsufficientHostCapacity/InsufficientCapacity mean transient capacity pressure
    on an otherwise-quota'd family. A second bounded pass after a short, fixed wait covers
    the transient case without pinning a numeric quota anywhere."""
    last_exc = None
    for attempt in range(passes):
        for az in azs:
            for instance_type in instance_types:
                try:
                    host_id = ec2.allocate_hosts(
                        AvailabilityZone=az,
                        InstanceType=instance_type,
                        Quantity=1,
                        AutoPlacement="off",
                        TagSpecifications=tag_spec,
                    )["HostIds"][0]
                    return host_id, instance_type, az
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code in ("HostLimitExceeded", "InsufficientHostCapacity", "InsufficientCapacity"):
                        last_exc = exc
                        continue
                    raise
        if attempt + 1 < passes:
            time.sleep(retry_interval_s)
    raise AssertionError(
        f"no (AZ, instance family) combination out of AZs={azs} and families="
        f"({', '.join(instance_types)}) has available Dedicated Host quota/capacity in "
        f"this account/region after {passes} pass(es): {last_exc}"
    )


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
