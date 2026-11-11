"""host-reservation-purchase-preview-cost-accuracy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "host-reservation-purchase-preview-cost-accuracy"
GROUP = "data-plane"
SERVICES = ["ec2"]

_INSTANCE_FAMILY = "c5"


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetHostReservationPurchasePreview's pricing figures are internally consistent with the host/offering."""
    ec2 = ctx.client("ec2")
    az = _pick_availability_zone(ec2)

    # A real, well-formed, but no-longer-owned host id: AWS's host-id format validation
    # rejects any hand-crafted id - even a random-looking one of the right length and
    # alphabet - as malformed before an existence lookup ever runs, so the only way to
    # reach the existence check is a genuine AWS-issued id. Allocate one and release it
    # immediately; its id is reused below once it is actually gone.
    unowned_host_id = ec2.allocate_hosts(
        AvailabilityZone=az,
        InstanceFamily=_INSTANCE_FAMILY,
        Quantity=1,
        AutoPlacement="on",
        TagSpecifications=[
            {
                "ResourceType": "dedicated-host",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-host-gone-")}],
            }
        ],
    )["HostIds"][0]
    ec2.release_hosts(HostIds=[unowned_host_id])

    # This account's Dedicated Host limit for this family is 1, and AWS's own
    # HostLimitExceeded message says a released host keeps counting against that limit for
    # a short grace period - retry the real allocation until the throwaway's slot frees up.
    host_id = _poll_until(
        lambda: _try_allocate_host(ec2, az, ctx),
        lambda result: result is not None,
        timeout_s=240.0,
        interval_s=15.0,
    )
    ctx.on_cleanup(lambda: ec2.release_hosts(HostIds=[host_id]))

    _poll_until(
        lambda: ec2.describe_hosts(HostIds=[host_id])["Hosts"][0]["State"],
        lambda state: state == "available",
        timeout_s=120.0,
        interval_s=5.0,
    )

    offerings = ec2.describe_host_reservation_offerings(
        Filter=[{"Name": "instance-family", "Values": [_INSTANCE_FAMILY]}]
    )["OfferingSet"]
    assert offerings, f"no host reservation offerings available for instance family {_INSTANCE_FAMILY!r}"
    offering = offerings[0]
    offering_id = offering["OfferingId"]

    preview = ec2.get_host_reservation_purchase_preview(HostIdSet=[host_id], OfferingId=offering_id)
    purchases = preview["Purchase"]
    assert len(purchases) == 1, f"expected exactly one purchase line for one host, got {purchases!r}"
    purchase = purchases[0]
    assert purchase["HostIdSet"] == [host_id], purchase

    total_hourly = float(preview["TotalHourlyPrice"])
    total_upfront = float(preview["TotalUpfrontPrice"])
    purchase_hourly = float(purchase["HourlyPrice"])
    purchase_upfront = float(purchase["UpfrontPrice"])
    # With a single host in the preview, the aggregate totals must equal that one purchase line.
    assert abs(total_hourly - purchase_hourly) < 1e-6, (
        f"TotalHourlyPrice {total_hourly} does not match the single purchase line {purchase_hourly}"
    )
    assert abs(total_upfront - purchase_upfront) < 1e-6, (
        f"TotalUpfrontPrice {total_upfront} does not match the single purchase line {purchase_upfront}"
    )

    # Negative (same setup): an unowned host ID must be rejected outright, not silently
    # dropped from the preview.
    code = _error_code(
        lambda: ec2.get_host_reservation_purchase_preview(
            HostIdSet=[host_id, unowned_host_id], OfferingId=offering_id
        )
    )
    assert code == "InvalidHostID.NotFound", f"expected InvalidHostID.NotFound, got {code!r}"

    # Positive control still holds after the rejected call.
    preview_again = ec2.get_host_reservation_purchase_preview(
        HostIdSet=[host_id], OfferingId=offering_id
    )
    assert preview_again["Purchase"][0]["HostIdSet"] == [host_id], (
        f"expected the preview to still cover {host_id!r} after the rejected call, "
        f"got {preview_again['Purchase'][0]['HostIdSet']!r}"
    )


def _pick_availability_zone(ec2) -> str:
    resp = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )
    zones = resp["AvailabilityZones"]
    assert zones, "no available Availability Zones in this region"
    return zones[0]["ZoneName"]


def _try_allocate_host(ec2, az: str, ctx) -> str | None:
    try:
        return ec2.allocate_hosts(
            AvailabilityZone=az,
            InstanceFamily=_INSTANCE_FAMILY,
            Quantity=1,
            AutoPlacement="on",
            TagSpecifications=[
                {
                    "ResourceType": "dedicated-host",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-host-")}],
                }
            ],
        )["HostIds"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "HostLimitExceeded":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for condition, last value {value!r}")


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
