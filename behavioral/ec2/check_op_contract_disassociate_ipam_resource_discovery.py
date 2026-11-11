"""op-contract-disassociate-ipam-resource-discovery."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociate-ipam-resource-discovery"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DisassociateIpamResourceDiscovery removes a resource discovery's
    association with an IPAM (the association reaches disassociate-complete);
    DryRun reports DryRunOperation without changing state."""
    ec2 = ctx.client("ec2")

    # Create the resource discovery before the IPAM: CreateIpam adds a default discovery that counts
    # against the per-Region quota of 1. The default association is tied to the IPAM, and
    # DisassociateIpamResourceDiscovery refuses it.
    rd_name = ctx.unique_name("sim2real-ipamrd-")
    rd_id = ec2.create_ipam_resource_discovery(
        Description=rd_name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {"ResourceType": "ipam-resource-discovery", "Tags": [{"Key": "Name", "Value": rd_name}]}
        ],
    )["IpamResourceDiscovery"]["IpamResourceDiscoveryId"]
    ctx.on_cleanup(lambda: _teardown_resource_discovery(ec2, rd_id))

    _poll_until(
        lambda: ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[rd_id])[
            "IpamResourceDiscoveries"
        ][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=120.0,
        interval_s=5.0,
    )

    ipam_name = ctx.unique_name("sim2real-ipam-")
    ipam_id = ec2.create_ipam(
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ipam_name}]}],
    )["Ipam"]["IpamId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True)))

    # Mutating calls against an IPAM's associations fail with IncorrectState until the IPAM
    # reaches create-complete, so wait for that terminal state first.
    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=120.0,
        interval_s=5.0,
    )

    assoc = ec2.associate_ipam_resource_discovery(IpamId=ipam_id, IpamResourceDiscoveryId=rd_id)[
        "IpamResourceDiscoveryAssociation"
    ]
    assoc_id = assoc["IpamResourceDiscoveryAssociationId"]

    def _assoc_state():
        # After disassociation, a describe by the association ID can return nothing or raise
        # InvalidIpamResourceDiscoveryAssociationId.NotFound; both mean gone (None).
        from botocore.exceptions import ClientError

        try:
            assocs = ec2.describe_ipam_resource_discovery_associations(
                IpamResourceDiscoveryAssociationIds=[assoc_id]
            )["IpamResourceDiscoveryAssociations"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidIpamResourceDiscoveryAssociationId.NotFound":
                return None
            raise
        return assocs[0]["State"] if assocs else None

    _poll_until(_assoc_state, lambda state: state == "associate-complete", timeout_s=120.0, interval_s=5.0)

    # Error boundary: DryRun must report DryRunOperation without disassociating.
    code, message = _client_error(
        lambda: ec2.disassociate_ipam_resource_discovery(
            IpamResourceDiscoveryAssociationId=assoc_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    post_dry_run_state = _assoc_state()
    assert post_dry_run_state == "associate-complete", (
        f"DryRun must not mutate the association; expected associate-complete, got {post_dry_run_state}"
    )

    resp = ec2.disassociate_ipam_resource_discovery(IpamResourceDiscoveryAssociationId=assoc_id)
    assert resp["IpamResourceDiscoveryAssociation"]["IpamResourceDiscoveryAssociationId"] == assoc_id, resp

    _poll_until(
        _assoc_state,
        lambda state: state in (None, "disassociate-complete"),
        timeout_s=120.0,
        interval_s=5.0,
    )


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidIpamId.NotFound",
            "InvalidIpamResourceDiscoveryAssociationId.NotFound",
        ):
            raise


def _teardown_resource_discovery(ec2, rd_id: str, timeout_s: float = 300.0) -> None:
    """Delete a resource discovery the check created. DeleteIpamResourceDiscovery is refused while
    any association still holds it, and disassociation is ASYNC, so remove the associations, wait
    for them to clear, then retry the delete under one bounded budget."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def _assocs():
        return [
            a
            for a in ec2.describe_ipam_resource_discovery_associations(
                Filters=[{"Name": "ipam-resource-discovery-id", "Values": [rd_id]}]
            )["IpamResourceDiscoveryAssociations"]
            if a.get("State") not in ("disassociate-complete",)
        ]

    for assoc in _assocs():
        if assoc.get("State") not in ("disassociate-in-progress",):
            _safe(lambda a=assoc: ec2.disassociate_ipam_resource_discovery(
                IpamResourceDiscoveryAssociationId=a["IpamResourceDiscoveryAssociationId"]
            ))
    while _assocs() and time.monotonic() < deadline:
        time.sleep(2)
    while True:
        try:
            ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=rd_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "InvalidIpamResourceDiscoveryId.NotFound":
                return
            if code not in ("IncorrectState",) or time.monotonic() >= deadline:
                raise RuntimeError(
                    f"delete_ipam_resource_discovery({rd_id}): {code}"
                ) from exc
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
