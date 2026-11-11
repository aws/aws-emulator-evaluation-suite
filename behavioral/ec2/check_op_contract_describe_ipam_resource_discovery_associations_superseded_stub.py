"""op-contract-describe-ipam-resource-discovery-associations-superseded-stub."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-resource-discovery-associations-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamResourceDiscoveryAssociations shows a new IPAM's default resource discovery as an
    active default association, which DescribeIpamResourceDiscoveries confirms as default and
    create-complete; DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-behav-ipamrda2-"),
        Tier="free",
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    default_rd_id = ipam["DefaultResourceDiscoveryId"]

    assoc = _poll_until(
        lambda: _first_association(ec2, ipam_id),
        lambda item: item is not None and item["ResourceDiscoveryStatus"] == "active",
        timeout_s=60.0,
    )
    assert assoc is not None, "no resource discovery association reached active for the new IPAM"
    assert assoc["IpamId"] == ipam_id, f"expected IpamId {ipam_id!r}, got {assoc['IpamId']!r}"
    assert assoc["IpamResourceDiscoveryId"] == default_rd_id, (
        f"expected the association to name the IPAM's own default resource discovery "
        f"{default_rd_id!r}, got {assoc['IpamResourceDiscoveryId']!r}"
    )
    assert assoc["IsDefault"] is True, f"expected IsDefault True, got {assoc['IsDefault']!r}"
    assert assoc["ResourceDiscoveryStatus"] == "active", assoc

    # Independent read through a *different* operation: the resource discovery
    # object itself must corroborate what the association claims about it.
    rd = ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[default_rd_id])[
        "IpamResourceDiscoveries"
    ][0]
    assert rd["IsDefault"] is True, f"expected the default resource discovery's own record to say IsDefault True, got {rd['IsDefault']!r}"
    assert rd["State"] == "create-complete", (
        f"expected the resource discovery's own State to be create-complete once its "
        f"association is active, got {rd['State']!r}"
    )

    code, message = _error(lambda: ec2.describe_ipam_resource_discovery_associations(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


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
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
