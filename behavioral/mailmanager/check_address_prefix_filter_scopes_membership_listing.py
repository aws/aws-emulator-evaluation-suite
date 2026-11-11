"""address-prefix-filter-scopes-membership-listing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "address-prefix-filter-scopes-membership-listing"
GROUP = 'address-list-members'
SERVICES = ['mailmanager']


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Filtering ListMembersOfAddressList by AddressPrefix returns exactly the
    addresses sharing that prefix, excluding the others registered alongside them.
    """
    mm = ctx.client("mailmanager")
    al_id = mm.create_address_list(
        AddressListName=ctx.unique_name("sim2real-behav-mm-al-")
    )["AddressListId"]
    ctx.on_cleanup(lambda: mm.delete_address_list(AddressListId=al_id))

    prefix = ctx.unique_name("alpha-")
    matching = {f"{prefix}{i}@example.com" for i in range(2)}
    other = {f"{ctx.unique_name('beta-')}@example.com"}
    for address in matching | other:
        mm.register_member_to_address_list(AddressListId=al_id, Address=address)

    unfiltered = {
        a["Address"]
        for page in mm.get_paginator("list_members_of_address_list").paginate(AddressListId=al_id)
        for a in page["Addresses"]
    }
    assert unfiltered == matching | other, f"unfiltered listing was {sorted(unfiltered)}"

    filtered = {
        a["Address"]
        for page in mm.get_paginator("list_members_of_address_list").paginate(
            AddressListId=al_id, Filter={"AddressPrefix": prefix}
        )
        for a in page["Addresses"]
    }
    assert filtered == matching, (
        f"filtering by prefix {prefix!r} returned {sorted(filtered)}, expected {sorted(matching)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
