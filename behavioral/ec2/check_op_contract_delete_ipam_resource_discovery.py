"""op-contract-delete-ipam-resource-discovery."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-ipam-resource-discovery"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIpamResourceDiscovery: DryRun boundary + real delete removes a standalone,
    unassociated (non-default) resource discovery, and the dead id then rejects a second
    delete with the specific not-found code."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-ipam-rd-")
    rd = ec2.create_ipam_resource_discovery(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {"ResourceType": "ipam-resource-discovery", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["IpamResourceDiscovery"]
    rd_id = rd["IpamResourceDiscoveryId"]
    ctx.on_cleanup(lambda: _safe_delete(ec2, rd_id))

    rd = _poll_until(
        lambda: ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[rd_id])[
            "IpamResourceDiscoveries"
        ][0],
        lambda r: r["State"] == "create-complete",
        timeout_s=60,
    )
    assert rd["IsDefault"] is False, f"expected a non-default resource discovery, got IsDefault={rd['IsDefault']!r}"

    # error boundary: DryRun short-circuits with DryRunOperation, resource discovery survives
    code, message = _error(
        lambda: ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=rd_id, DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    still_there = ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[rd_id])[
        "IpamResourceDiscoveries"
    ][0]
    assert still_there["State"] == "create-complete", (
        f"expected create-complete after DryRun, got {still_there['State']!r}"
    )

    # success path: an unassociated, non-default resource discovery deletes cleanly
    resp = ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=rd_id)
    assert resp["IpamResourceDiscovery"]["IpamResourceDiscoveryId"] == rd_id, (
        f"expected delete response to echo {rd_id}, "
        f"got {resp['IpamResourceDiscovery']['IpamResourceDiscoveryId']!r}"
    )
    assert resp["IpamResourceDiscovery"]["State"] in ("delete-in-progress", "delete-complete"), (
        f"expected a delete state, got {resp['IpamResourceDiscovery']['State']!r}"
    )

    _poll_until(
        lambda: _describe_rds_tolerant(ec2, rd_id),
        lambda rds: (not rds) or rds[0]["State"] == "delete-complete",
        timeout_s=60,
    )

    # the id is now dead: a second delete on it must fail with the specific not-found
    # code, not silently succeed or 200 again
    dead_code, dead_message = _error(
        lambda: ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=rd_id)
    )
    assert dead_code == "InvalidIpamResourceDiscoveryId.NotFound", f"unexpected code {dead_code!r}"
    assert dead_message == f"The ipam-resource-discovery ID '{rd_id}' does not exist", f"unexpected message {dead_message!r}"


def _describe_rds_tolerant(ec2, rd_id):
    # once the resource discovery is truly gone, DescribeIpamResourceDiscoveries raises
    # NotFound instead of returning an empty list - treat that as "deleted" for polling.
    try:
        return ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[rd_id])[
            "IpamResourceDiscoveries"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamResourceDiscoveryId.NotFound":
            return []
        raise


def _safe_delete(ec2, rd_id):
    try:
        ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=rd_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamResourceDiscoveryId.NotFound":
            raise


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
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
