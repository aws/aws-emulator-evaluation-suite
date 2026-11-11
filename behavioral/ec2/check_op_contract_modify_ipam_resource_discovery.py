"""op-contract-modify-ipam-resource-discovery."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ipam-resource-discovery"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyIpamResourceDiscovery updates its description/operating regions and rejects an unknown id."""
    ec2 = ctx.client("ec2")
    discovery = ec2.create_ipam_resource_discovery(
        Description="initial",
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {
                "ResourceType": "ipam-resource-discovery",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ipam-rd-")}],
            }
        ],
    )["IpamResourceDiscovery"]
    discovery_id = discovery["IpamResourceDiscoveryId"]

    def _cleanup():
        try:
            ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=discovery_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidIpamResourceDiscoveryId.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    discovery = _poll_until(
        lambda: ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[discovery_id])[
            "IpamResourceDiscoveries"
        ][0],
        lambda d: d["State"] == "create-complete",
        timeout_s=60,
        interval_s=3,
    )
    assert discovery["IsDefault"] is False, (
        f"a freshly created resource discovery must not be the account default, got {discovery!r}"
    )

    # success path
    resp = ec2.modify_ipam_resource_discovery(
        IpamResourceDiscoveryId=discovery_id, Description="updated-by-sim2real"
    )
    updated = resp["IpamResourceDiscovery"]
    assert updated["Description"] == "updated-by-sim2real", (
        f"expected modify response to echo 'updated-by-sim2real', got {updated['Description']!r}"
    )

    described = ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[discovery_id])[
        "IpamResourceDiscoveries"
    ][0]
    assert described["Description"] == "updated-by-sim2real", (
        f"expected independent read to reflect the update, got {described['Description']!r}"
    )

    # error boundary: unknown resource discovery id
    code, message = _error(
        lambda: ec2.modify_ipam_resource_discovery(
            IpamResourceDiscoveryId="ipam-res-disco-00000000000000000", Description="x"
        )
    )
    assert code == "InvalidIpamResourceDiscoveryId.NotFound", f"expected NotFound code, got {code}"
    assert message == "The ipam-resource-discovery ID 'ipam-res-disco-00000000000000000' does not exist", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
