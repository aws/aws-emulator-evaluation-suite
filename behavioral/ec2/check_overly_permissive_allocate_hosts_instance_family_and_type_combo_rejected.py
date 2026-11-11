"""overly-permissive-allocate-hosts-instance-family-and-type-combo-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-allocate-hosts-instance-family-and-type-combo-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AllocateHosts rejects a request naming both InstanceFamily and InstanceType, which AWS documents
    as mutually exclusive, after a positive control allocates a host with InstanceType alone; only the
    control's host exists under the check's tag afterward."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[
            {"Name": "region-name", "Values": [ctx.region]},
            {"Name": "state", "Values": ["available"]},
        ]
    )["AvailabilityZones"][0]["ZoneName"]

    tag_value = ctx.unique_name("sim2real-behav-host-")
    tag_spec = [
        {
            "ResourceType": "dedicated-host",
            "Tags": [
                {"Key": "Name", "Value": tag_value},
                {"Key": "sim2real-check", "Value": CHECK},
            ],
        }
    ]

    # Positive control: the same request shape with only one of the two
    # mutually-exclusive fields set must succeed, so the rejection below is
    # attributable to the illegal combination, not to AllocateHosts refusing
    # every request in this account/region.
    host_id = _allocate_host_with_retry(
        ec2,
        dict(
            AvailabilityZone=az,
            InstanceType="c5.large",
            Quantity=1,
            AutoPlacement="off",
            TagSpecifications=tag_spec,
        ),
    )
    ctx.on_cleanup(lambda: ec2.release_hosts(HostIds=[host_id]))
    described = ec2.describe_hosts(HostIds=[host_id])["Hosts"][0]
    assert described["AvailabilityZone"] == az, described

    # distinct error boundary: specifying both InstanceFamily and
    # InstanceType together must be rejected, not silently resolved by
    # picking one of them. Real AWS surfaces this specific combination
    # under the generic InvalidRequest code rather than
    # InvalidParameterCombination.
    code = _error_code(
        lambda: ec2.allocate_hosts(
            AvailabilityZone=az,
            InstanceFamily="c5",
            InstanceType="c5.large",
            Quantity=1,
            AutoPlacement="off",
        )
    )
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}"

    # effect-absent: the rejected combo must not have allocated a second
    # host -- only the positive control's host exists under this check's tag.
    live = ec2.describe_hosts(
        Filters=[
            {"Name": "tag:sim2real-check", "Values": [CHECK]},
            {"Name": "state", "Values": ["available", "under-assessment", "pending"]},
        ]
    )["Hosts"]
    assert [h["HostId"] for h in live] == [host_id], live


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _allocate_host_with_retry(ec2, alloc_kwargs, *, timeout_s=120.0, interval_s=10.0):
    """AllocateHosts against a low per-account Dedicated Host limit.

    A prior interrupted run of this same check can leak an allocated host that still
    counts against the account's host limit. Rather than assuming the limit is always
    free, self-heal by releasing any leaked hosts tagged from earlier runs of this check
    and waiting out the full bound before giving up.
    """
    deadline = time.monotonic() + timeout_s
    released_leaked = False
    last_error = None
    while True:
        try:
            return ec2.allocate_hosts(**alloc_kwargs)["HostIds"][0]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("HostLimitExceeded", "InsufficientHostCapacity", "InsufficientCapacity"):
                raise
            last_error = exc

        if not released_leaked:
            leaked = ec2.describe_hosts(
                Filters=[
                    {"Name": "tag:sim2real-check", "Values": [CHECK]},
                    {"Name": "state", "Values": ["available", "under-assessment", "permanent-failure"]},
                ]
            )["Hosts"]
            leaked_ids = [h["HostId"] for h in leaked if not h.get("Instances")]
            if leaked_ids:
                ec2.release_hosts(HostIds=leaked_ids)
            released_leaked = True

        if time.monotonic() >= deadline:
            raise AssertionError(
                "no Dedicated Host capacity/quota available for the positive control even "
                f"after self-healing leaked hosts tagged by this check: {last_error}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
