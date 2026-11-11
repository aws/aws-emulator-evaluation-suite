"""ipam-internet-registry-association-asns-matches-association."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipam-internet-registry-association-asns-matches-association"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamInternetRegistryAssociationAsns lists an empty ASN set for a created association, and
    fails Malformed for an invalid id and NotFound for a mutated well-formed id, each with its exact
    message.
    """
    ec2 = ctx.client("ec2")
    ipam_id = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-behav-ipam-"),
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {
                "ResourceType": "ipam",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ipam-")}],
            }
        ],
    )["Ipam"]["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    assoc = ec2.create_ipam_internet_registry_association(
        IpamId=ipam_id,
        Rir="arin",
        OrganizationHandle=ctx.unique_name("sim2real-org-"),
        ClientToken=ctx.unique_name("sim2real-behav-assoc-"),
    )["IpamInternetRegistryAssociation"]
    association_id = assoc["IpamInternetRegistryAssociationId"]
    ctx.on_cleanup(lambda: _delete_association(ec2, association_id))

    # Positive control: the real association's own ASN set is reachable and
    # genuinely empty -- proves the API isn't just erroring on every input.
    resp = ec2.get_ipam_internet_registry_association_asns(
        IpamInternetRegistryAssociationId=association_id
    )
    asns = resp.get("IpamInternetRegistryAssociationAsns")
    assert asns == [], f"expected the real association's own ASN set to be empty, got {asns!r}"

    # A syntactically invalid id must never yield fabricated (or borrowed) ASNs.
    invalid_id = "not-a-valid-association-id"
    invalid_code, invalid_message = _error(
        lambda: ec2.get_ipam_internet_registry_association_asns(
            IpamInternetRegistryAssociationId=invalid_id
        )
    )
    assert invalid_code == "InvalidIpamInternetRegistryAssociationId.Malformed", f"unexpected error code {invalid_code!r}"
    assert invalid_message == (
        f"The ipam-internet-registry-association ID '{invalid_id}' is malformed"
    ), f"unexpected error message {invalid_message!r}"

    # A well-formed but nonexistent id -- built by mutating the real, live id
    # returned above -- must be rejected too, never silently answered as if
    # it were the real association above.
    nonexistent_id = _mutate_id(association_id)
    nonexistent_code, nonexistent_message = _error(
        lambda: ec2.get_ipam_internet_registry_association_asns(
            IpamInternetRegistryAssociationId=nonexistent_id
        )
    )
    assert nonexistent_code == "InvalidIpamInternetRegistryAssociationId.NotFound", (
        f"unexpected error code {nonexistent_code!r} for a nonexistent association id"
    )
    assert nonexistent_message == (
        f"The ipam-internet-registry-association ID '{nonexistent_id}' does not exist"
    ), (
        f"unexpected error message {nonexistent_message!r} for a nonexistent association id"
    )


def _mutate_id(real_id: str) -> str:
    last = real_id[-1]
    return real_id[:-1] + ("0" if last != "0" else "1")


def _delete_association(ec2, association_id: str) -> None:
    """Teardown: delete the association, retrying while it is still create-in-progress."""
    import time

    deadline = time.monotonic() + 120
    while True:
        try:
            ec2.delete_ipam_internet_registry_association(
                IpamInternetRegistryAssociationId=association_id
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState" or time.monotonic() > deadline:
                raise
        time.sleep(5)


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
