"""address-normalization-lowercases-domain-preserves-local-part."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "address-normalization-lowercases-domain-preserves-local-part"
GROUP = 'address-list-members'
SERVICES = ['mailmanager']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering an address with a mixed-case domain stores it with the domain
    lowercased and the local part's case preserved, in both the list and the get.
    """
    mm = ctx.client("mailmanager")
    al_id = mm.create_address_list(
        AddressListName=ctx.unique_name("sim2real-behav-mm-al-")
    )["AddressListId"]
    ctx.on_cleanup(lambda: mm.delete_address_list(AddressListId=al_id))

    local_part = ctx.unique_name("MixedCase-")
    written = f"{local_part}@EXAMPLE.com"
    normalized = f"{local_part}@example.com"

    mm.register_member_to_address_list(AddressListId=al_id, Address=written)

    listed = mm.list_members_of_address_list(AddressListId=al_id)["Addresses"]
    assert len(listed) == 1, f"expected exactly one member, got {listed!r}"
    assert listed[0]["Address"] == normalized, (
        f"expected the stored address {normalized!r} (domain lowercased, local part "
        f"preserved), got {listed[0]['Address']!r}"
    )

    got = mm.get_member_of_address_list(AddressListId=al_id, Address=normalized)
    assert got["Address"] == normalized, f"get returned {got['Address']!r}, expected {normalized!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
