"""ipam-routing-policy-registration-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ipam-routing-policy-registration-round-trip"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """An IPAM internet registry association describes back with its exact IpamId, Rir,
    OrganizationHandle and Description and an empty ASN list, CreateIpamRoutingPolicyRegistration on
    it fails IncorrectState with its exact message, and it is gone after delete.
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

    org_handle = ctx.unique_name("sim2real-org-")
    description = "sim2real-behav-registry-association"
    created = ec2.create_ipam_internet_registry_association(
        IpamId=ipam_id,
        Rir="ripe",
        OrganizationHandle=org_handle,
        Description=description,
        TagSpecifications=[
            {"ResourceType": "ipam-internet-registry-association", "Tags": [{"Key": "Name", "Value": description}]}
        ],
    )["IpamInternetRegistryAssociation"]
    assoc_id = created["IpamInternetRegistryAssociationId"]
    ctx.on_cleanup(lambda: _delete_association_if_present(ec2, assoc_id))

    assert created["IpamId"] == ipam_id, f"expected IpamId {ipam_id!r}, got {created['IpamId']!r}"
    # The request accepts the RIR enum lowercase ("ripe"), but real AWS echoes it back
    # upper-cased in every response -- the Smithy model's documented enum value is wrong.
    assert created["Rir"] == "RIPE", f"expected Rir 'RIPE', got {created['Rir']!r}"
    assert created["OrganizationHandle"] == org_handle, (
        f"expected OrganizationHandle {org_handle!r}, got {created['OrganizationHandle']!r}"
    )
    assert created["Description"] == description, (
        f"expected Description {description!r}, got {created['Description']!r}"
    )
    assert created["State"] in (
        "pending-enable",
        "create-in-progress",
        "create-failed",
        "enable-in-progress",
        "enable-complete",
        "enable-failed",
    ), f"unexpected post-create State {created['State']!r}"

    # The create response is not enough on its own -- confirm the fields were actually persisted by
    # reading them back through an independent describe call.
    described = _describe_association(ec2, assoc_id)
    assert described is not None, "association is not visible in DescribeIpamInternetRegistryAssociations"
    assert described["Rir"] == "RIPE", f"expected persisted Rir 'RIPE', got {described['Rir']!r}"
    assert described["OrganizationHandle"] == org_handle, (
        f"expected persisted OrganizationHandle {org_handle!r}, got {described['OrganizationHandle']!r}"
    )
    assert described["Description"] == description, (
        f"expected persisted Description {description!r}, got {described['Description']!r}"
    )
    assert described["IpamId"] == ipam_id, f"expected persisted IpamId {ipam_id!r}, got {described['IpamId']!r}"

    asns = ec2.get_ipam_internet_registry_association_asns(IpamInternetRegistryAssociationId=assoc_id)
    assert asns["IpamInternetRegistryAssociationAsns"] == [], (
        "a freshly created association with no completed RIR activation must not report any ASNs"
    )

    # CreateIpamRoutingPolicyRegistration needs the association in 'enable-complete', which takes
    # an RIR BPKI handshake. The refusal names the association's state, so the create phase settles
    # first; DeleteIpamInternetRegistryAssociation also rejects an association still mid-create.
    settled = _wait_association_state_settled(ec2, assoc_id)
    rejection_code, rejection_message = _error(
        lambda: ec2.create_ipam_routing_policy_registration(
            IpamInternetRegistryAssociationId=assoc_id,
            Cidr="198.51.100.0/24",
            Asns=["64512"],
        )
    )
    assert rejection_code == "IncorrectState", (
        f"expected CreateIpamRoutingPolicyRegistration to reject a non-enable-complete association "
        f"with IncorrectState, got {rejection_code!r}"
    )
    expected_message = (
        f"The specified action is not valid. The Internet Registry association {assoc_id} "
        f"is in an invalid state {settled['State']}."
    )
    assert rejection_message == expected_message, (
        f"expected message {expected_message!r}, got {rejection_message!r}"
    )

    ec2.delete_ipam_internet_registry_association(IpamInternetRegistryAssociationId=assoc_id)

    # Poll to the terminal outcome: the association passes through delete-in-progress and is then
    # gone (describe answers NotFound) or reads delete-complete.
    deadline = time.monotonic() + 300
    remaining = None
    while time.monotonic() < deadline:
        remaining = _describe_association(ec2, assoc_id)
        if remaining is None or remaining["State"] == "delete-complete":
            return
        time.sleep(5)
    raise AssertionError(f"deleted internet registry association never left the listing: {remaining!r}")


def _wait_association_state_settled(ec2, assoc_id, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_association(ec2, assoc_id)
        if last is not None and last["State"] != "create-in-progress":
            return last
        time.sleep(3)
    raise AssertionError(f"association {assoc_id} stuck in create-in-progress (last={last!r})")


def _wait_ipam_state(ec2, ipam_id, state, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ipam = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]
        if ipam["State"] == state:
            return
        time.sleep(3)
    raise AssertionError(f"IPAM never reached state {state!r}")


def _delete_association_if_present(ec2, assoc_id):
    """Teardown: the body deletes the association on the pass path, so a NotFound here is done."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_ipam_internet_registry_association(IpamInternetRegistryAssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamInternetRegistryAssociationId.NotFound":
            raise


def _describe_association(ec2, assoc_id):
    """The association, or None once describe no longer knows the id."""
    from botocore.exceptions import ClientError

    try:
        resp = ec2.describe_ipam_internet_registry_associations(IpamInternetRegistryAssociationIds=[assoc_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamInternetRegistryAssociationId.NotFound":
            return None
        raise
    associations = resp.get("IpamInternetRegistryAssociations", [])
    return associations[0] if associations else None


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
