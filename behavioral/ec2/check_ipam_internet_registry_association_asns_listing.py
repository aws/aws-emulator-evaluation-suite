"""ipam-internet-registry-association-asns-listing."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ipam-internet-registry-association-asns-listing"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """Two internet registry associations (ARIN and APNIC) created under one IPAM each list an empty
    ASN set with no NextToken from GetIpamInternetRegistryAssociationAsns and describe back with
    their own Rir and distinct ids.
    """
    ec2 = ctx.client("ec2")
    ipam_name = ctx.unique_name("sim2real-behav-ipam-")
    ipam_id = ec2.create_ipam(
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ipam_name}]}],
    )["Ipam"]["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    _wait_ipam_state(ec2, ipam_id, "create-complete")

    assoc_a_id = _create_association(ctx, ec2, ipam_id, "arin")
    assoc_b_id = _create_association(ctx, ec2, ipam_id, "apnic")

    asns_a = ec2.get_ipam_internet_registry_association_asns(IpamInternetRegistryAssociationId=assoc_a_id)
    asns_b = ec2.get_ipam_internet_registry_association_asns(IpamInternetRegistryAssociationId=assoc_b_id)

    assert asns_a["IpamInternetRegistryAssociationAsns"] == [], "association A should report no ASNs"
    assert asns_b["IpamInternetRegistryAssociationAsns"] == [], "association B should report no ASNs"
    assert not asns_a.get("NextToken"), "an empty ASN listing must not claim there is another page"
    assert not asns_b.get("NextToken"), "an empty ASN listing must not claim there is another page"

    # Cross-check isolation: describing association A must never surface association B's RIR, and
    # vice versa -- catches an emulator that conflates distinct associations under the same IPAM.
    described_a = _describe_association(ec2, assoc_a_id)
    described_b = _describe_association(ec2, assoc_b_id)
    # Real AWS echoes Rir back upper-cased (observed "ARIN" for a created "arin"), so the
    # comparison is case-insensitive -- the invariant under test is which RIR was stored, not casing.
    assert described_a["Rir"].upper() == "ARIN", f"expected association A Rir 'arin', got {described_a['Rir']!r}"
    assert described_b["Rir"].upper() == "APNIC", f"expected association B Rir 'apnic', got {described_b['Rir']!r}"
    assert described_a["IpamInternetRegistryAssociationId"] != described_b["IpamInternetRegistryAssociationId"], (
        "association A and B must not report the same IpamInternetRegistryAssociationId"
    )


def _wait_ipam_state(ec2, ipam_id, state, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ipam = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]
        if ipam["State"] == state:
            return
        time.sleep(3)
    raise AssertionError(f"IPAM never reached state {state!r}")


def _create_association(ctx, ec2, ipam_id, rir):
    name = f"sim2real-behav-{rir}"
    assoc = ec2.create_ipam_internet_registry_association(
        IpamId=ipam_id,
        Rir=rir,
        OrganizationHandle=ctx.unique_name("sim2real-org-"),
        Description=name,
        TagSpecifications=[
            {"ResourceType": "ipam-internet-registry-association", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["IpamInternetRegistryAssociation"]
    assoc_id = assoc["IpamInternetRegistryAssociationId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_internet_registry_association(IpamInternetRegistryAssociationId=assoc_id))
    return assoc_id


def _describe_association(ec2, assoc_id):
    resp = ec2.describe_ipam_internet_registry_associations(IpamInternetRegistryAssociationIds=[assoc_id])
    associations = resp["IpamInternetRegistryAssociations"]
    if not associations:
        raise AssertionError(f"describe_ipam_internet_registry_associations returned no association for {assoc_id!r}")
    return associations[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
