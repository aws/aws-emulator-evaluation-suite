"""op-contract-release-hosts."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-release-hosts"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# Dedicated Host quotas are granted per instance-family group and independently adjustable; a
# fresh/sandbox account can genuinely have a 0 quota for one family (e.g. m5) while another family
# is available. Try a small set of common families instead of hardcoding one that may not have any
# quota in this account/region.
_CANDIDATE_HOST_TYPES = ("m5.large", "c5.large", "r5.large", "m6i.large", "c6i.large")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReleaseHosts releases an idle Dedicated Host (Successful, state "released") and reports a host with
    a running instance as Unsuccessful with Client.InvalidHost.Occupied, leaving it allocated; once the
    instance is terminated the same call releases it."""
    ec2 = ctx.client("ec2")

    # The occupying instance launches into the run's shared network, so hosts go in its zones.
    azs = ctx.network().availability_zones

    # Dedicated Host quotas are low and per-account/region: a prior run of this same check that
    # failed mid-test (e.g. before its cleanup ran) can leave an idle host allocated, which then
    # causes AllocateHosts here to hit HostLimitExceeded. Reclaim any such leaked hosts (tagged by
    # this check) before allocating new ones.
    _release_stale_hosts(ec2)

    host_tag = [{"Key": "sim2real-check", "Value": CHECK}]

    # --- success path: release an idle Dedicated Host ---
    idle_host_id, instance_type, az = _allocate_host_with_fallback(ec2, azs, host_tag)
    idle_released = False

    def _cleanup_idle():
        if not idle_released:
            _release_host(ec2, idle_host_id)

    ctx.on_cleanup(_cleanup_idle)

    resp = ec2.release_hosts(HostIds=[idle_host_id])
    idle_released = True
    assert resp["Successful"] == [idle_host_id], resp
    assert resp["Unsuccessful"] == [], resp

    # The batch response only claims success; confirm it at the destination via an independent
    # DescribeHosts read rather than trusting ReleaseHosts's own report of itself.
    idle_state = _wait_for_host_state(ec2, idle_host_id, {"released"})
    assert idle_state == "released", f"expected {idle_host_id} to reach 'released', got {idle_state!r}"

    # --- error boundary: release a host that is occupied by a running instance ---
    # The just-released host keeps counting toward its family's Dedicated Host quota for a while
    # (HostLimitExceeded at a quota of 1), so the occupied host may come from another family or
    # zone; the instance placed on it uses that host's type and zone. `azs` holds only the shared
    # network's zones (set above), so ctx.network().subnets[az] always exists.
    occupied_host_id, instance_type, az = _allocate_host_with_fallback(ec2, azs, host_tag)
    occupied_released = False

    def _cleanup_occupied():
        if not occupied_released:
            _release_host(ec2, occupied_host_id)

    ctx.on_cleanup(_cleanup_occupied)

    ami_id = _latest_al2023_ami(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        Placement={"AvailabilityZone": az, "Tenancy": "host", "HostId": occupied_host_id},
        SubnetId=ctx.network().subnets[az],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-host-")}]}
        ],
    )["Instances"][0]["InstanceId"]
    instance_terminated = False

    def _cleanup_instance():
        if not instance_terminated:
            _terminate_instance(ec2, instance_id)

    ctx.on_cleanup(_cleanup_instance)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    resp = ec2.release_hosts(HostIds=[occupied_host_id])
    assert resp["Successful"] == [], resp
    assert len(resp["Unsuccessful"]) == 1, f"expected exactly one Unsuccessful entry, got {resp}"
    unsuccessful = resp["Unsuccessful"][0]
    assert unsuccessful["ResourceId"] == occupied_host_id, (
        f"expected the Unsuccessful entry to name {occupied_host_id}, got {unsuccessful}"
    )
    assert unsuccessful["Error"]["Code"] == "Client.InvalidHost.Occupied", unsuccessful

    # Effect-absent: an independent read must show the occupied host was NOT released -- a target
    # that merely fakes the "Unsuccessful" entry without actually blocking the release would still
    # pass the assertions above unless we check the destination.
    occupied_host = ec2.describe_hosts(HostIds=[occupied_host_id])["Hosts"][0]
    assert occupied_host["State"] != "released", (
        f"expected {occupied_host_id} to remain un-released while occupied, got state {occupied_host['State']!r}"
    )
    assert instance_id in [i["InstanceId"] for i in occupied_host.get("Instances", [])], (
        f"expected {instance_id} to still be reported on {occupied_host_id}, got {occupied_host.get('Instances')}"
    )

    # --- restore: remove the occupation and demand the identical call now succeeds ---
    _terminate_instance(ec2, instance_id)
    instance_terminated = True

    resp = ec2.release_hosts(HostIds=[occupied_host_id])
    assert resp["Successful"] == [occupied_host_id], (
        f"expected ReleaseHosts to succeed for {occupied_host_id} once its instance was terminated, got {resp}"
    )
    assert resp["Unsuccessful"] == [], f"expected no failures once unoccupied, got {resp}"
    occupied_released = True

    restored_state = _wait_for_host_state(ec2, occupied_host_id, {"released"})
    assert restored_state == "released", (
        f"expected {occupied_host_id} to reach 'released' after the restored release, got {restored_state!r}"
    )


def _allocate_host_with_fallback(ec2, azs, host_tag, instance_types=_CANDIDATE_HOST_TYPES, retries_per_combo=3, retry_interval_s=5.0):
    """Allocate one Dedicated Host, trying each (AZ, instance family) combination in turn and
    moving on when the account/region/AZ has no usable capacity for that specific combination --
    either because of zero quota for the family (HostLimitExceeded) or because Dedicated Host
    capacity for that family in that AZ is transiently unavailable (InsufficientHostCapacity /
    InsufficientCapacity, both verified for real). Since Dedicated Host capacity is a live, shared
    resource that can free up within seconds, retry each combination a bounded number of times
    before moving on. Any other error is a real failure and propagates immediately."""
    last_exc = None
    for az in azs:
        for instance_type in instance_types:
            for attempt in range(retries_per_combo):
                try:
                    host_id = ec2.allocate_hosts(
                        InstanceType=instance_type,
                        Quantity=1,
                        AvailabilityZone=az,
                        AutoPlacement="off",
                        TagSpecifications=[{"ResourceType": "dedicated-host", "Tags": host_tag}],
                    )["HostIds"][0]
                    return host_id, instance_type, az
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code in ("HostLimitExceeded", "InsufficientHostCapacity", "InsufficientCapacity"):
                        last_exc = exc
                        if attempt + 1 < retries_per_combo:
                            time.sleep(retry_interval_s)
                        continue
                    raise
    raise AssertionError(
        f"no (AZ, instance family) combination out of AZs={azs} and families="
        f"({', '.join(instance_types)}) has available quota/capacity in this account/region: {last_exc}"
    )


def _release_stale_hosts(ec2):
    hosts = ec2.describe_hosts(
        Filters=[
            {"Name": "tag:sim2real-check", "Values": [CHECK]},
            {"Name": "state", "Values": ["available", "under-assessment"]},
        ]
    )["Hosts"]
    idle_ids = [h["HostId"] for h in hosts if not h.get("Instances")]
    if idle_ids:
        ec2.release_hosts(HostIds=idle_ids)


def _latest_al2023_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _terminate_instance(ec2, instance_id):
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise
        return
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200}
    )


def _wait_for_host_state(ec2, host_id, expected_states, timeout_s=120.0, interval_s=5.0):
    """Poll DescribeHosts (an independent read of ReleaseHosts's own batch response) until host_id
    reaches one of expected_states, bounded by timeout_s. Raises on timeout rather than returning
    the last-observed state."""
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        hosts = ec2.describe_hosts(HostIds=[host_id])["Hosts"]
        last_state = hosts[0]["State"] if hosts else "absent"
        if last_state in expected_states:
            return last_state
        time.sleep(interval_s)
    raise AssertionError(
        f"host {host_id} did not reach a state in {expected_states} within {timeout_s}s; "
        f"last observed {last_state!r}"
    )


def _release_host(ec2, host_id, timeout_s=300.0, interval_s=10.0):
    """Release a Dedicated Host, retrying while its instance is still terminating; raise if the
    host is still allocated at the deadline (an idle host bills by the hour)."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = ec2.release_hosts(HostIds=[host_id])
        if resp["Successful"]:
            return
        hosts = ec2.describe_hosts(HostIds=[host_id])["Hosts"]
        if not hosts or hosts[0]["State"] in ("released", "released-permanent-failure"):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"Dedicated Host {host_id} still allocated after {timeout_s}s: {resp['Unsuccessful']}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
