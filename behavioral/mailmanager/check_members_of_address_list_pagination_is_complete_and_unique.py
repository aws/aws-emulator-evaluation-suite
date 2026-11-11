"""members-of-address-list-pagination-is-complete-and-unique."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "members-of-address-list-pagination-is-complete-and-unique"
GROUP = 'address-list-members'
SERVICES = ['mailmanager']

_COUNT = 5
_PAGE_SIZE = 2


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListMembersOfAddressList with a page smaller than the member count
    returns every registered address exactly once, with no page over its size.
    """
    mm = ctx.client("mailmanager")
    al_id = mm.create_address_list(
        AddressListName=ctx.unique_name("sim2real-behav-mm-al-")
    )["AddressListId"]
    ctx.on_cleanup(lambda: mm.delete_address_list(AddressListId=al_id))

    expected = {f"{ctx.unique_name('member-')}@example.com" for _ in range(_COUNT)}
    assert len(expected) == _COUNT, "unique_name collided; the fixture itself is broken"
    for address in expected:
        mm.register_member_to_address_list(AddressListId=al_id, Address=address)

    pages = list(
        mm.get_paginator("list_members_of_address_list").paginate(
            AddressListId=al_id, PageSize=_PAGE_SIZE
        )
    )
    seen: list[str] = []
    for page in pages:
        addresses = page["Addresses"]
        assert len(addresses) <= _PAGE_SIZE, f"page returned {len(addresses)} > PageSize {_PAGE_SIZE}"
        seen.extend(a["Address"] for a in addresses)

    assert len(seen) == len(set(seen)), f"pagination returned a duplicate among {seen!r}"
    assert set(seen) == expected, f"paginated set {sorted(seen)} != registered set {sorted(expected)}"
    assert len(pages) >= 2, f"expected PageSize {_PAGE_SIZE} over {_COUNT} members to span multiple pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
