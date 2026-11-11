"""op-contract-describe-ipam-resource-discovery-associations."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-resource-discovery-associations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamResourceDiscoveryAssociations filtered by a new IPAM's ID returns its default discovery
    as an active default association, an unknown ipam-id matches nothing, and DryRun answers
    DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-behav-ipamrda-"),
        Tier="free",
        TagSpecifications=[
            {
                "ResourceType": "ipam",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ipamrda-")}],
            }
        ],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    default_rd_id = ipam["DefaultResourceDiscoveryId"]
    ctx.on_cleanup(lambda: _delete_ipam(ec2, ipam_id))

    # Success path: the default resource discovery association for this IPAM must appear,
    # scoped correctly by the ipam-id filter, and settle into an active state.
    assoc = _poll_until(
        lambda: _first_association(ec2, ipam_id),
        lambda item: item is not None and item["ResourceDiscoveryStatus"] == "active",
        timeout_s=60.0,
    )
    assert assoc["IpamId"] == ipam_id, f"expected ipam-id {ipam_id!r}, got {assoc['IpamId']!r}"
    assert assoc["ResourceDiscoveryStatus"] == "active", (
        f"expected active, got {assoc['ResourceDiscoveryStatus']!r}"
    )
    assert assoc["IsDefault"] is True, f"expected the default association, got IsDefault={assoc['IsDefault']!r}"
    assert assoc["IpamResourceDiscoveryId"] == default_rd_id, (
        f"association points at {assoc['IpamResourceDiscoveryId']!r}, "
        f"but the IPAM's own DefaultResourceDiscoveryId is {default_rd_id!r}"
    )

    # Filtering by an unrelated, well-formed ipam-id must yield no rows, not an error.
    resp = ec2.describe_ipam_resource_discovery_associations(
        Filters=[{"Name": "ipam-id", "Values": ["ipam-0000000000000000"]}]
    )
    assert resp["IpamResourceDiscoveryAssociations"] == [], (
        f"expected no rows for an unrelated ipam-id, got {resp['IpamResourceDiscoveryAssociations']!r}"
    )

    # Error boundary: DryRun.
    code, message = _error(lambda: ec2.describe_ipam_resource_discovery_associations(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _delete_ipam(ec2, ipam_id, timeout_s=900.0):
    """Cascade-delete the IPAM and wait until it is gone, so it stops holding the per-Region IPAM
    quota; not-found means gone, delete-failed and any other error raise."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamId.NotFound":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ipams = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidIpamId.NotFound":
                return
            raise
        state = ipams[0]["State"] if ipams else "delete-complete"
        if state == "delete-complete":
            return
        if state == "delete-failed" or time.monotonic() >= deadline:
            raise RuntimeError(f"IPAM {ipam_id} not deleted (state {state})")
        time.sleep(2)


def _first_association(ec2, ipam_id):
    rows = ec2.describe_ipam_resource_discovery_associations(
        Filters=[{"Name": "ipam-id", "Values": [ipam_id]}]
    )["IpamResourceDiscoveryAssociations"]
    return rows[0] if rows else None


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
