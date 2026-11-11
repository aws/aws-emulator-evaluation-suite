"""default-ipam-resource-discovery-deletion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-ipam-resource-discovery-deletion-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamResourceDiscovery of an IPAM's default resource discovery is refused with IncorrectState and its
    exact message and the discovery stays create-complete, while a standalone non-default discovery deletes.
    """
    ec2 = ctx.client("ec2")

    control_rd = ec2.create_ipam_resource_discovery(
        Description=ctx.unique_name("sim2real-ipam-rd-control-"),
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {"ResourceType": "ipam-resource-discovery", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )["IpamResourceDiscovery"]
    control_rd_id = control_rd["IpamResourceDiscoveryId"]
    ctx.on_cleanup(lambda: _safe_delete(ec2, control_rd_id))

    control_rd = _poll_until(
        lambda: ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[control_rd_id])[
            "IpamResourceDiscoveries"
        ][0],
        lambda r: r["State"] == "create-complete",
        timeout_s=60,
    )
    assert control_rd["IsDefault"] is False, (
        f"expected a standalone resource discovery to not be default, got IsDefault={control_rd['IsDefault']!r}"
    )

    ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=control_rd_id)
    _poll_until(
        lambda: _describe_rds_tolerant(ec2, control_rd_id),
        lambda rds: (not rds) or rds[0]["State"] == "delete-complete",
        timeout_s=60,
    )

    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-ipam-rdreject-"),
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    default_rd_id = ipam["DefaultResourceDiscoveryId"]
    assert default_rd_id, "IPAM reached create-complete but reported no DefaultResourceDiscoveryId"

    default_rd = ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[default_rd_id])[
        "IpamResourceDiscoveries"
    ][0]
    assert default_rd["IsDefault"] is True, (
        f"expected the IPAM's auto-created resource discovery to be default, got IsDefault={default_rd['IsDefault']!r}"
    )

    err = _client_error(
        lambda: ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=default_rd_id)
    )
    assert err.get("Code") == "IncorrectState", (
        f"expected a default-resource-discovery-protection error, got {err!r}"
    )
    assert err.get("Message") == (
        f"The specified action is not valid. The resource discovery {default_rd_id} is a default resource discovery."
    ), (
        f"unexpected default-resource-discovery refusal message: {err!r}"
    )

    # it must still exist and still be usable/associated after the rejected attempt
    still_there = ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[default_rd_id])[
        "IpamResourceDiscoveries"
    ][0]
    assert still_there["State"] == "create-complete", (
        f"expected the default resource discovery to remain create-complete after the rejected "
        f"delete, got State={still_there['State']!r}"
    )


def _describe_rds_tolerant(ec2, rd_id):
    # Once the resource discovery is gone, DescribeIpamResourceDiscoveries raises NotFound
    # rather than returning an empty list; that counts as deleted.
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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
