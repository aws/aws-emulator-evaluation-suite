"""deregister-member-is-idempotent-for-unknown-and-removed-addresses."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-member-is-idempotent-for-unknown-and-removed-addresses"
GROUP = 'address-list-members'
SERVICES = ['mailmanager']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterMemberFromAddressList is a no-op, not an error, for an address that
    was never registered and for one already removed by an earlier call.
    """
    mm = ctx.client("mailmanager")
    al_id = mm.create_address_list(
        AddressListName=ctx.unique_name("sim2real-behav-mm-al-")
    )["AddressListId"]
    ctx.on_cleanup(lambda: mm.delete_address_list(AddressListId=al_id))

    never_registered = f"{ctx.unique_name('never-')}@example.com"
    mm.deregister_member_from_address_list(AddressListId=al_id, Address=never_registered)

    registered = f"{ctx.unique_name('removed-')}@example.com"
    mm.register_member_to_address_list(AddressListId=al_id, Address=registered)
    mm.get_member_of_address_list(AddressListId=al_id, Address=registered)  # positive control

    mm.deregister_member_from_address_list(AddressListId=al_id, Address=registered)
    try:
        mm.get_member_of_address_list(AddressListId=al_id, Address=registered)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ResourceNotFoundException", f"after deregistering, the get raised {err['Code']!r}"
        expected_message = f"Could not find Address in AddressList {al_id} of AWS account {ctx.account}"
        assert err["Message"] == expected_message, f"unexpected message {err['Message']!r}"
    else:
        raise AssertionError("the deregistered address is still readable")

    # A second deregistration of the now-absent address is still a no-op, not an error.
    mm.deregister_member_from_address_list(AddressListId=al_id, Address=registered)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
